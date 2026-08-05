"""
A suite of tests for the `apikeys` module, focusing on limits, users, and compilation.

This module contains test cases for verifying the functionality of key components of
the `apikeys` library. These include reading and validating rate-limiting configurations,
managing user API keys, and generating compiled output for a Caddy server. Tests are
organized into sections that correspond to specific responsibilities.

It relies on external test data and uses fixtures to manage temporary directories.

```yaml
Modules imported:
- `os`: Provides operating system functionality such as environment variable checks.
- `textwrap`: Used to dedent multiline strings for clarity.
- `pathlib`: Facilitates interactions with the filesystem and paths.
- `pytest`: A testing framework used to define and parameterize test cases.
- `yaml`: Used for parsing YAML files within the tests.
- `apikeys`: The library under test, which manages API key configurations.

Constants:
- `TESTDATA`: Directory holding golden files for comparison in some tests.
- `KEY_A` and `KEY_B`: Mock API keys used in parameterized tests.
- `LIMITS`: YAML configuration string that defines rate-limiting tiers and endpoints.
```

Functions
---------

write(tmp_path, name, content):
    Writes the given content to a specified file name within a temporary directory.

    Args:
        tmp_path (pathlib.Path): A pytest-supplied temporary directory.
        name (str): The name of the file to write.
        content (str): The content to write to the file.

    Returns:
        str: The file path as a string.

csv(text):
    Strips leading whitespace and formats a CSV text using mock API keys.

    Args:
        text (str): A CSV string with placeholders for keys.

    Returns:
        str: The formatted CSV text.

bad_limits(tmp_path, mutate):
    Creates an invalid limits configuration by mutating valid limits data.

    Args:
        tmp_path (pathlib.Path): A pytest-supplied temporary directory.
        mutate (callable): A function that mutates the loaded YAML document.

    Returns:
        str: Path to the invalid limits file.

rename_standard_tier(doc):
    Renames the "standard" tier to "silver" in the given limits configuration.

    Args:
        doc (dict): A limits configuration document.

Test Cases
----------

test_read_limits(limits):
    Verifies the correct parsing of a valid limits configuration.

test_read_limits_rejects(tmp_path, mutate, expected):
    Ensures invalid configurations are rejected and appropriate errors are raised.

test_read_limits_rejects_unparseable(tmp_path, content):
    Confirms errors are raised for malformed or unparseable YAML files.

test_read_users(tmp_path, limits, content, expected):
    Verifies user data is correctly parsed and matches expected output.

test_read_users_rejects(tmp_path, limits, content, expected):
    Ensures errors are raised for invalid or malformed user data.

test_read_users_errors_never_contain_key_material(tmp_path, limits):
    Validates that error messages related to user data do not expose sensitive key material.

test_dump_users_preserves_every_key(tmp_path, limits):
    Confirms that dumping user data does not lose or alter any keys.

test_compile_matches_golden(tmp_path, limits, users, golden):
    Checks that compiled output matches golden files for various tier configurations.
"""

import os
import textwrap
from pathlib import Path

import pytest
import yaml

import apikeys
from apikeys import ConfigError, User


TESTDATA = Path(__file__).parent / "testdata"

KEY_A = "a" * 64
KEY_B = "b" * 64

LIMITS = textwrap.dedent(
    """
    window: 1d
    tiers:
      unauthorized: { matcher: "@noApiKey",       key: "{remote_host}",          multiplier: 1 }
      standard:     { matcher: "@standardApiKey", key: "{header.Authorization}", multiplier: 100 }
      premium:      { matcher: "@premiumApiKey",  key: "{header.Authorization}", multiplier: 500 }
    endpoints:
      - { name: register_identity, path: "*/time/register_identity*", method: POST, base: 5 }
      - { name: get_decryption_key, path: "*/time/get_decryption_key*", method: GET, base: 20 }
    """
)


def write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return str(p)


def csv(text):
    return textwrap.dedent(text).lstrip().format(A=KEY_A, B=KEY_B)


def bad_limits(tmp_path, mutate):
    doc = yaml.safe_load(LIMITS)
    mutate(doc)
    return write(tmp_path, "limits.yaml", yaml.safe_dump(doc))


@pytest.fixture
def limits(tmp_path):
    return apikeys.read_limits(write(tmp_path, "limits.yaml", LIMITS))


def rename_standard_tier(doc):
    doc["tiers"]["silver"] = doc["tiers"].pop("standard")


# --- read_limits ------------------------------------------------------------------


def test_read_limits(limits):
    assert limits.window == "1d"
    assert limits.assignable_tiers == ["standard", "premium"]
    register, decryption_key = limits.endpoints
    assert limits.events(register, "unauthorized") == 5
    assert limits.events(register, "standard") == 500
    assert limits.events(register, "premium") == 2500
    assert limits.events(decryption_key, "premium") == 10000


@pytest.mark.parametrize(
    "mutate,expected",
    [
        pytest.param(
            lambda doc: doc["tiers"]["standard"].update(multiplier=0),
            "multiplier",
            id="multiplier of zero",
        ),
        pytest.param(
            lambda doc: doc["tiers"]["standard"].update(multiplier="100"),
            "multiplier",
            id="quoted multiplier",
        ),
        pytest.param(
            lambda doc: doc["tiers"]["standard"].pop("matcher"),
            "matcher",
            id="tier with no matcher",
        ),
        pytest.param(
            lambda doc: doc["endpoints"][0].pop("base"),
            "base",
            id="endpoint with no base",
        ),
        pytest.param(rename_standard_tier, "standard", id="no standard tier"),
        pytest.param(lambda doc: doc.pop("tiers"), "tiers", id="no tiers section"),
        pytest.param(lambda doc: doc.pop("endpoints"), "endpoints", id="no endpoints"),
    ],
)
def test_read_limits_rejects(tmp_path, mutate, expected):
    with pytest.raises(ConfigError, match=expected):
        apikeys.read_limits(bad_limits(tmp_path, mutate))


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("window: 1d\ntiers: [\n", id="broken yaml"),
        pytest.param("", id="empty file"),
        pytest.param("- a\n- b\n", id="a list rather than a mapping"),
    ],
)
def test_read_limits_rejects_unparseable(tmp_path, content):
    with pytest.raises(ConfigError):
        apikeys.read_limits(write(tmp_path, "limits.yaml", content))


# --- read_users -------------------------------------------------------------------


@pytest.mark.parametrize(
    "content,expected",
    [
        pytest.param(
            csv(
                """
                username,apikey,tier
                alice,{A},standard
                bob,{B},premium
                """
            ),
            {"alice": User(KEY_A, "standard"), "bob": User(KEY_B, "premium")},
            id="a key on each tier",
        ),
        pytest.param(
            csv(
                """
                username,apikey
                alice,{A}
                """
            ),
            {"alice": User(KEY_A, "standard")},
            id="two columns, as written before tiers existed",
        ),
        pytest.param(
            csv(
                """
                username,apikey
                alice,{A}
                bob,{B},premium
                """
            ),
            {"alice": User(KEY_A, "standard"), "bob": User(KEY_B, "premium")},
            id="half migrated, after promoting one key by hand",
        ),
        pytest.param("", {}, id="empty file"),
    ],
)
def test_read_users(tmp_path, limits, content, expected):
    assert apikeys.read_users(limits, write(tmp_path, "keys.csv", content)) == expected


@pytest.mark.parametrize(
    "content,expected",
    [
        pytest.param(
            csv("username,apikey,tier\nalice,{A},premiun\n"),
            "premiun",
            id="misspelled tier",
        ),
        pytest.param(
            "username,apikey,tier\nalice,tooshort,standard\n",
            "alice",
            id="truncated key",
        ),
        pytest.param(
            csv("username,apikey,tier\nalice,{A},standard,extra\n"),
            "alice",
            id="stray comma",
        ),
    ],
)
def test_read_users_rejects(tmp_path, limits, content, expected):
    with pytest.raises(ConfigError, match=expected):
        apikeys.read_users(limits, write(tmp_path, "keys.csv", content))


def test_read_users_errors_never_contain_key_material(tmp_path, limits):
    truncated = KEY_A[:10]
    keys = write(
        tmp_path, "keys.csv", f"username,apikey,tier\nalice,{truncated},standard\n"
    )
    with pytest.raises(ConfigError) as e:
        apikeys.read_users(limits, keys)
    assert "alice" in str(e.value)
    assert truncated not in str(e.value)


# --- dump_users -------------------------------------------------------------------


def test_dump_users_preserves_every_key(tmp_path, limits):
    keys = write(
        tmp_path,
        "keys.csv",
        csv(
            """
            username,apikey,tier
            alice,{A},standard
            bob,{B},premium
            """
        ),
    )
    before = apikeys.read_users(limits, keys)

    apikeys.dump_users(before, keys)

    assert open(keys).readline().strip() == "username,apikey,tier"
    assert apikeys.read_users(limits, keys) == before


# --- compile ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "users,golden",
    [
        pytest.param(
            {"alice": User(KEY_A, "standard"), "bob": User(KEY_B, "premium")},
            "snippet_both_tiers.caddy",
            id="a key on each tier",
        ),
        pytest.param(
            {"alice": User(KEY_A, "standard")},
            "snippet_empty_premium.caddy",
            id="no premium keys",
        ),
    ],
)
def test_compile_matches_golden(tmp_path, limits, users, golden):
    out = tmp_path / "apikeys.caddy"
    apikeys.compile(dict(users), limits, str(out))
    produced = out.read_text()

    expected = TESTDATA / golden
    if os.environ.get("UPDATE_GOLDEN"):
        TESTDATA.mkdir(exist_ok=True)
        expected.write_text(produced)

    assert produced == expected.read_text()