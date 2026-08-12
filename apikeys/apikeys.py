#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "pyyaml",
# ]
# ///

"""
Utility for handling API keys and rate limits with caddy. There are two functions:
    - generating new keys and store them in the user database .csv (${KEYS_FILE})
    - compiling a Caddyfile snippet for using those keys (${CADDY_SNIPPET})

Without arguments it is started interactively and will ask for a reference for a new
key (e.g. an email) and which tier to put it on.

If used in a docker-compose setup, it can be run with the `--compile` flag, that will
non-interactively compile the `Caddyfile` snippet to use.

Tiers
-----
Each key sits on a tier, which decides its rate limits. The tiers and their limits are
defined in ${LIMITS_FILE} (see limits.yaml); the key database records which tier each
key is on, in a third column:

    username,apikey,tier
    alice@example.com,<64 hex chars>,standard
    bob@example.com,<64 hex chars>,premium

Rows with no tier column read as standard, so a database written before tiers existed
still works and a deploy stays reversible. To move a key between tiers, edit that
column and re-run with --compile.

The compiled snippet contains both the API key matchers and the rate limit zones —
limits are not configured as caddy labels in docker-compose, so the whole policy lives
in one readable file. Every compile prints the limits it produced.
"""

import os
import sys
import secrets
from typing import Any, Dict, List, NamedTuple, Optional

import yaml


KEYS_FILE = os.environ.get("KEYS_FILE", "users.csv")
CADDY_SNIPPET = os.environ.get("CADDY_SNIPPET", "apikeys")
LIMITS_FILE = os.environ.get("LIMITS_FILE", "limits.yaml")

# The tier for requests with no key. It has no entries in keys.csv: its matcher is
# built by inverting every known key, and it is counted per IP rather than per key.
UNAUTHENTICATED_TIER = "unauthorized"

# Every key is on this tier unless keys.csv says otherwise, including rows written
# before the tier column existed.
DEFAULT_TIER = "standard"

# Sole condition of a tier matcher with no keys in it. A named matcher with no
# conditions matches every request, which would hand that tier's limits to
# unauthenticated traffic — so an empty tier gets a condition nothing satisfies.
NEVER_MATCHES = "no-keys-in-this-tier"

TAB = "\t"


class ConfigError(Exception):
    """Bad input in the key database or the limits file."""


class User(NamedTuple):
    key: str
    tier: str


class Limits(NamedTuple):
    window: str
    tiers: Dict[str, Dict[str, Any]]  # tier -> {matcher, key, multiplier}
    endpoints: List[Dict[str, Any]]

    @property
    def assignable_tiers(self) -> List[str]:
        """Tiers a key can be put on — everything except the no-key tier."""
        return [t for t in self.tiers if t != UNAUTHENTICATED_TIER]

    def events(self, endpoint: Dict[str, Any], tier: str) -> int:
        return endpoint["base"] * self.tiers[tier]["multiplier"]


def generate_token() -> str:
    return secrets.token_hex(32)


def read_limits(path: Optional[str] = None) -> Limits:
    path = path or LIMITS_FILE
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError:
        raise ConfigError(f"Limits file '{path}' not found")
    except yaml.YAMLError as e:
        raise ConfigError(f"'{path}' is not valid YAML: {e}")

    if not isinstance(raw, dict):
        raise ConfigError(f"'{path}' must be a mapping with window, tiers and endpoints")

    for field in ("window", "tiers", "endpoints"):
        if not raw.get(field):
            raise ConfigError(f"'{path}' is missing '{field}'")

    for tier, cfg in raw["tiers"].items():
        for field in ("matcher", "key", "multiplier"):
            if cfg.get(field) is None:
                raise ConfigError(f"Tier '{tier}' in '{path}' is missing '{field}'")
        if not isinstance(cfg["multiplier"], int) or cfg["multiplier"] < 1:
            raise ConfigError(
                f"Tier '{tier}' has multiplier {cfg['multiplier']!r}; must be a "
                f"positive integer"
            )

    for endpoint in raw["endpoints"]:
        for field in ("name", "path", "method", "base"):
            if endpoint.get(field) is None:
                raise ConfigError(
                    f"Endpoint entry in '{path}' is missing '{field}': {endpoint}"
                )
        if not isinstance(endpoint["base"], int) or endpoint["base"] < 1:
            raise ConfigError(
                f"Endpoint '{endpoint['name']}' has base {endpoint['base']!r}; must "
                f"be a positive integer"
            )

    limits = Limits(str(raw["window"]), raw["tiers"], raw["endpoints"])
    if DEFAULT_TIER not in limits.assignable_tiers:
        raise ConfigError(f"'{path}' must define a '{DEFAULT_TIER}' tier")
    return limits


def read_users(limits: Limits, path: Optional[str] = None) -> Dict[str, User]:
    """Read the key database. Rows are `username,apikey[,tier]`.

    The tier column is optional; a two-column row reads as standard.
    """
    path = path or KEYS_FILE
    try:
        with open(path) as f:
            rows = [line.strip().split(",") for line in f if line.strip()]
    except FileNotFoundError:
        return {}

    users: Dict[str, User] = {}
    for row in rows:
        if row[0].strip() == "username":  # header row, whatever its column count
            continue
        if len(row) == 2:
            name, key, tier = row[0], row[1], DEFAULT_TIER
        elif len(row) == 3:
            name, key, tier = row
        else:
            raise ConfigError(
                f"Malformed row in '{path}': expected username,apikey[,tier] — got "
                f"{len(row)} fields for '{row[0].strip()}'"
            )
        name, key, tier = name.strip(), key.strip(), tier.strip() or DEFAULT_TIER
        if tier not in limits.assignable_tiers:
            raise ConfigError(
                f"Unknown tier '{tier}' for '{name}'. Defined tiers: "
                f"{', '.join(limits.assignable_tiers)}"
            )
        users[name] = User(key, tier)

    # Name the users, not their keys — an error message is somewhere key material
    # should never end up.
    malformed = [name for name, u in users.items() if len(u.key) < 64]
    if malformed:
        raise ConfigError(f"Malformed keys for: {', '.join(malformed)}")
    return users


def dump_users(users: Dict[str, User], path: Optional[str] = None) -> None:
    path = path or KEYS_FILE
    with open(path, "wb") as f:
        f.write(b"username,apikey,tier\n")
        f.writelines(
            [f"{name},{u.key},{u.tier}\n".encode() for name, u in users.items()]
        )
    print(f"Wrote user database to '{path}'")


def write_matcher(f, name: str, users: Dict[str, User], negate: bool = False) -> None:
    """Write a named matcher matching any one of the given keys.

    Caddy ORs multiple values for the same header field, so listing every key
    means "any of these". It ANDs separate conditions, which is what turns the
    negated form into "none of these".
    """
    prefix = "not " if negate else ""
    f.write(f"@{name} {{\n".encode())
    if not users:
        f.write(f"{TAB}#no keys in this tier\n".encode())
        f.write(f'{TAB}{prefix}header Authorization "Bearer {NEVER_MATCHES}"\n'.encode())
    for user, u in users.items():
        f.write(f"{TAB}#api key for {user}\n".encode())
        f.write(f'{TAB}{prefix}header Authorization "Bearer {u.key}"\n'.encode())
    f.write(b"}\n\n")


def write_rate_limits(f, limits: Limits) -> None:
    """Write one rate_limit block per tier, with one zone per endpoint."""
    for tier, cfg in limits.tiers.items():
        f.write(f"rate_limit {cfg['matcher']} {{\n".encode())
        # A bare flag. `log_key " "` is a caddy-docker-proxy idiom for a directive
        # with no arguments, and a parse error in Caddyfile syntax.
        f.write(f"{TAB}log_key\n".encode())
        for endpoint in limits.endpoints:
            f.write(f"{TAB}zone {endpoint['name']}__{tier} {{\n".encode())
            f.write(f"{TAB * 2}match {{\n".encode())
            f.write(f"{TAB * 3}path {endpoint['path']}\n".encode())
            f.write(f"{TAB * 3}method {endpoint['method']}\n".encode())
            f.write(f"{TAB * 2}}}\n".encode())
            f.write(f"{TAB * 2}key {cfg['key']}\n".encode())
            f.write(f"{TAB * 2}window {limits.window}\n".encode())
            f.write(f"{TAB * 2}events {limits.events(endpoint, tier)}\n".encode())
            f.write(f"{TAB}}}\n".encode())
        f.write(b"}\n\n")


def compile(users: Dict[str, User], limits: Limits, path: Optional[str] = None) -> None:
    path = path or CADDY_SNIPPET
    if len(users) == 0:
        users["THROWAWAY DO NOT USE!!!"] = User(generate_token(), DEFAULT_TIER)

    with open(path, "wb") as f:
        # Requests with no valid key: every key negated, so "none of these".
        write_matcher(f, "noApiKey", users, negate=True)
        # Any valid key regardless of tier. Rate limiting matches per tier, but
        # the /check_authentication handler still uses this one.
        write_matcher(f, "withApiKey", users)
        for tier in limits.assignable_tiers:
            write_matcher(
                f, f"{tier}ApiKey", {n: u for n, u in users.items() if u.tier == tier}
            )
        write_rate_limits(f, limits)

    print(f"Compiled Caddyfile snippet to '{path}'")
    print_resolved(users, limits)


def print_resolved(users: Dict[str, User], limits: Limits) -> None:
    """Print the resolved limits, which limits.yaml only holds as base × multiplier."""
    tiers = list(limits.tiers)
    width = max(len(e["name"]) for e in limits.endpoints)
    print(f"  {'endpoint':<{width}}" + "".join(f"{t:>14}" for t in tiers))
    for endpoint in limits.endpoints:
        row = f"  {endpoint['name']:<{width}}"
        for tier in tiers:
            row += f"{limits.events(endpoint, tier):>14}"
        print(row)
    counts = ", ".join(
        f"{t}={sum(1 for u in users.values() if u.tier == t)}"
        for t in limits.assignable_tiers
    )
    print(f"  per {limits.window}, keys per tier: {counts}")


def main() -> None:
    limits = read_limits()

    if len(sys.argv) > 1 and sys.argv[1] == "--compile":
        compile(read_users(limits), limits)
        return

    user = input(
        "User reference (e.g. email) for new key. Empty for only compiling Caddyfile snippet: "
    ).strip()
    users = read_users(limits)
    if len(user) > 0 and len(user) < 3:
        sys.exit("User name needs to be >=3 characters")
    if user in users.keys():
        sys.exit("User name not unique")
    if len(user):
        options = "/".join(limits.assignable_tiers)
        tier = (
                input(f"Tier for this key ({options}) [{DEFAULT_TIER}]: ").strip()
                or DEFAULT_TIER
        )
        if tier not in limits.assignable_tiers:
            sys.exit(f"Unknown tier '{tier}'. Expected one of: {options}")
        users[user] = User(generate_token(), tier)
        dump_users(users)
    compile(users, limits)


if __name__ == "__main__":
    try:
        main()
    except ConfigError as e:
        sys.exit(str(e))