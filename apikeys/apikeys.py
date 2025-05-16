#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

"""
Utility for handling API keys with caddy. There are two functions:
    - generating new keys and store them in the user database .csv (${KEYS_FILE})
    - compiling a Caddyfile snippet for using those keys (${CADDY_SNIPPET})

Without arguments it is started interactively and will ask for a reference for a new key.

If used in a docker-compose setup, it can be run with the `--compile` flag, that will
non-interactively compile the `Caddyfile` snippet to use.
"""

import os
import sys
import secrets
from typing import Dict


KEYS_FILE = os.environ.get("KEYS_FILE", "users.csv")
CADDY_SNIPPET = os.environ.get("CADDY_SNIPPET", "apikeys")


def generate_token() -> str:
    return secrets.token_hex(32)


def read_users() -> Dict[str, str]:
    try:
        with open(KEYS_FILE) as f:
            users = {
                name.strip(): key.strip()
                for name, key in [l.split(",") for l in f.readlines()]
            }
        if "username" in users:
            users.pop("username")
        if any(len(key) < 32 for key in users.values()):
            sys.exit(
                f"Malformed keys: {list(filter(lambda _: len(_) < 32, users.values()))}"
            )
        return users
    except FileNotFoundError:
        return {}


def dump_users(users: Dict[str, str]) -> None:
    with open(KEYS_FILE, "wb") as f:
        f.write(b"username,apikey\n")
        f.writelines([f"{user},{key}\n".encode() for user, key in users.items()])
    print(f"Wrote user database to '{KEYS_FILE}'")


def compile(users: Dict[str, str]) -> None:
    tab = "\t"
    if len(users) == 0:
        users["THROWAWAY DO NOT USE!!!"] = generate_token()
    with open(CADDY_SNIPPET, "wb") as f:
        f.write(b"@noApiKey {\n")
        for user, key in users.items():
            f.write(f"{tab}#api key for {user}\n".encode())
            f.write(f'{tab}not header Authorization "Bearer {key}"\n'.encode())
        f.write(b"}\n\n")
        f.write(b"@withApiKey {\n")
        for user, key in users.items():
            f.write(f"{tab}#api key for {user}\n".encode())
            f.write(f'{tab}header Authorization "Bearer {key}"\n'.encode())
        f.write(b"}\n\n")
    print(f"Compiled Caddyfile snippet to '{CADDY_SNIPPET}'")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--compile":
        users = read_users()
        compile(users)
        sys.exit(0)

    user = input(
        "User reference (e.g. email) for new key. Empty for only compiling Caddyfile snippet: "
    ).strip()
    users = read_users()
    if len(user) > 0 and len(user) < 3:
        sys.exit("User name needs to be >=3 characters")
    if user in users.keys():
        sys.exit("User name not unique")
    token = generate_token()
    if len(user):
        users[user] = token
        dump_users(users)
    compile(users)
