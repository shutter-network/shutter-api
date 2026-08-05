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
key is on, as a third column:

    username,apikey,tier
    alice@example.com,<64 hex chars>,standard
    bob@example.com,<64 hex chars>,premium

Rows with no tier column read as standard, so a database written before tiers existed
still works. To move an existing key between tiers, edit that column and re-run with
--compile.

The compiled snippet contains both the API key matchers and the rate limit zones —
limits are not configured as caddy labels in docker-compose, so the whole policy lives
in one readable file. Every compile prints the limits it produced.
"""

import os
import sys
import secrets
from typing import Any, Dict, List, NamedTuple

import yaml


KEYS_FILE = os.environ.get("KEYS_FILE", "users.csv")
CADDY_SNIPPET = os.environ.get("CADDY_SNIPPET", "apikeys")
LIMITS_FILE = os.environ.get("LIMITS_FILE", "limits.yaml")

# The tier for requests with no key. It has no entries in keys.csv: its matcher is
# built by inverting every known key, and it is counted per IP rather than per key.
UNAUTHENTICATED_TIER = "unauthorized"

# Sole condition of a tier matcher with no keys in it. A named matcher with no
# conditions matches every request, which would hand that tier's limits to
# unauthenticated traffic — so an empty tier gets a condition nothing satisfies.
NEVER_MATCHES = "no-keys-in-this-tier"

TAB = "\t"


class User(NamedTuple):
    key: str
    tier: str


class Limits(NamedTuple):
    window: str
    tiers: Dict[str, Dict[str, str]]  # tier -> {matcher, key}
    endpoints: List[Dict[str, Any]]

    @property
    def assignable_tiers(self) -> List[str]:
        """Tiers a key can be put on — everything except the no-key tier."""
        return [t for t in self.tiers if t != UNAUTHENTICATED_TIER]


def generate_token() -> str:
    return secrets.token_hex(32)


def read_limits() -> Limits:
    try:
        with open(LIMITS_FILE) as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError:
        sys.exit(f"Limits file '{LIMITS_FILE}' not found")

    for field in ("window", "tiers", "endpoints"):
        if not raw.get(field):
            sys.exit(f"'{LIMITS_FILE}' is missing '{field}'")

    for tier, cfg in raw["tiers"].items():
        for field in ("matcher", "key", "multiplier"):
            if cfg.get(field) is None:
                sys.exit(f"Tier '{tier}' in '{LIMITS_FILE}' is missing '{field}'")
        if not isinstance(cfg["multiplier"], int) or cfg["multiplier"] < 1:
            sys.exit(
                f"Tier '{tier}' has multiplier {cfg['multiplier']!r}; must be a "
                f"positive integer"
            )

    for endpoint in raw["endpoints"]:
        for field in ("name", "path", "method", "base"):
            if endpoint.get(field) is None:
                sys.exit(f"Endpoint entry in '{LIMITS_FILE}' is missing '{field}': {endpoint}")
        if not isinstance(endpoint["base"], int) or endpoint["base"] < 1:
            sys.exit(
                f"Endpoint '{endpoint['name']}' has base {endpoint['base']!r}; must "
                f"be a positive integer"
            )

    return Limits(str(raw["window"]), raw["tiers"], raw["endpoints"])


def read_users(limits: Limits) -> Dict[str, User]:
    """Read the key database. Rows are `username,apikey[,tier]`.

    The tier column is optional: a two-column row (the format before tiers
    existed) reads as standard, so an untouched keys.csv keeps working.
    """
    default_tier = "standard"
    if default_tier not in limits.assignable_tiers:
        sys.exit(f"'{LIMITS_FILE}' must define a '{default_tier}' tier")

    try:
        with open(KEYS_FILE) as f:
            rows = [line.strip().split(",") for line in f if line.strip()]
    except FileNotFoundError:
        return {}

    users: Dict[str, User] = {}
    for row in rows:
        if len(row) == 2:
            name, key, tier = row[0], row[1], default_tier
        elif len(row) == 3:
            name, key, tier = row
        else:
            sys.exit(f"Malformed row in '{KEYS_FILE}': {','.join(row)}")

        name, key, tier = name.strip(), key.strip(), tier.strip() or default_tier
        if name == "username":  # header row
            continue
        if tier not in limits.assignable_tiers:
            sys.exit(
                f"Unknown tier '{tier}' for '{name}'. '{LIMITS_FILE}' defines: "
                f"{', '.join(limits.assignable_tiers)}"
            )
        users[name] = User(key, tier)

    malformed = [u.key for u in users.values() if len(u.key) < 64]
    if malformed:
        sys.exit(f"Malformed keys: {malformed}")
    return users


def dump_users(users: Dict[str, User]) -> None:
    with open(KEYS_FILE, "wb") as f:
        f.write(b"username,apikey,tier\n")
        f.writelines(
            [f"{name},{u.key},{u.tier}\n".encode() for name, u in users.items()]
        )
    print(f"Wrote user database to '{KEYS_FILE}'")


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
        # A bare flag. The docker-compose labels this replaced spelled it
        # `log_key: " "` because caddy-docker-proxy uses a single-space value to
        # mean "directive with no arguments" — that space is not an argument, and
        # passing it through is a parse error in real Caddyfile syntax.
        f.write(f"{TAB}log_key\n".encode())
        for endpoint in limits.endpoints:
            f.write(f"{TAB}zone {endpoint['name']}__{tier} {{\n".encode())
            f.write(f"{TAB * 2}match {{\n".encode())
            f.write(f"{TAB * 3}path {endpoint['path']}\n".encode())
            f.write(f"{TAB * 3}method {endpoint['method']}\n".encode())
            f.write(f"{TAB * 2}}}\n".encode())
            f.write(f"{TAB * 2}key {cfg['key']}\n".encode())
            f.write(f"{TAB * 2}window {limits.window}\n".encode())
            f.write(f"{TAB * 2}events {endpoint['base'] * cfg['multiplier']}\n".encode())
            f.write(f"{TAB}}}\n".encode())
        f.write(b"}\n\n")


def compile(users: Dict[str, User], limits: Limits) -> None:
    if len(users) == 0:
        users["THROWAWAY DO NOT USE!!!"] = User(generate_token(), "standard")

    with open(CADDY_SNIPPET, "wb") as f:
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

    print(f"Compiled Caddyfile snippet to '{CADDY_SNIPPET}'")
    print_resolved(users, limits)


def print_resolved(users: Dict[str, User], limits: Limits) -> None:
    """Print the limits this compile actually produced.

    The YAML holds bases and multipliers, so the effective numbers are not
    visible by reading it. Printing them here keeps them accurate by
    construction — a comment stating them would go stale the first time someone
    changes a multiplier.
    """
    tiers = list(limits.tiers)
    width = max(len(e["name"]) for e in limits.endpoints)
    header = f"  {'endpoint':<{width}}" + "".join(f"{t:>14}" for t in tiers)
    print(header)
    for endpoint in limits.endpoints:
        row = f"  {endpoint['name']:<{width}}"
        for tier in tiers:
            row += f"{endpoint['base'] * limits.tiers[tier]['multiplier']:>14}"
        print(row)
    counts = ", ".join(
        f"{t}={sum(1 for u in users.values() if u.tier == t)}"
        for t in limits.assignable_tiers
    )
    print(f"  per {limits.window}, keys per tier: {counts}")


if __name__ == "__main__":
    limits = read_limits()

    if len(sys.argv) > 1 and sys.argv[1] == "--compile":
        compile(read_users(limits), limits)
        sys.exit(0)

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
        tier = input(f"Tier for this key ({options}) [standard]: ").strip() or "standard"
        if tier not in limits.assignable_tiers:
            sys.exit(f"Unknown tier '{tier}'. Expected one of: {options}")
        users[user] = User(generate_token(), tier)
        dump_users(users)
    compile(users, limits)