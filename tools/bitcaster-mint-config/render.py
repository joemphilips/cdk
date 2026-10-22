#!/usr/bin/env python3
"""Render an explicit local or staging fakewallet configuration without secrets."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from urllib.parse import urlsplit

MAX_INPUT_BYTES = 128 * 1024
MAX_INTEGER = 2**63 - 1  # TOML integers are signed 64-bit values.


class InputRefused(ValueError):
    """The input is outside the supported nonsecret profile."""


def require(condition):
    if not condition:
        raise InputRefused("input refused")


def text(value):
    require(type(value) is str and len(value) <= 8192)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise InputRefused("input refused") from None


def plain_text(value):
    text(value)
    require(bool(value) and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def integer(value):
    require(type(value) is int and 0 <= value <= MAX_INTEGER)


def positive(value):
    integer(value)
    require(value > 0)


def port(value):
    positive(value)
    require(value <= 65535)


def choice(*values):
    def validate(value):
        require(type(value) is type(values[0]) and value in values)
    return validate


def absolute_path(value):
    plain_text(value)
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) != "/" and ".." not in path.parts)


def secret_reference(value):
    plain_text(value)
    if value.startswith("env:"):
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value[4:]) is not None)
    elif value.startswith("file:"):
        absolute_path(value[5:])
    else:
        raise InputRefused("input refused")


def host(value):
    plain_text(value)
    require(re.fullmatch(r"[A-Za-z0-9.:-]+", value) is not None)


def public_url(value):
    plain_text(value)
    try:
        parsed = urlsplit(value)
        require(parsed.scheme in ("http", "https") and bool(parsed.hostname))
        host(parsed.hostname)
        require(parsed.username is None and parsed.password is None)
        require(not parsed.query and not parsed.fragment)
        if parsed.port is not None:
            port(parsed.port)
    except ValueError:
        raise InputRefused("input refused") from None


def object_fields(value, required, optional=None):
    optional = optional or {}
    require(type(value) is dict)
    require(set(required) <= value.keys() <= required.keys() | optional.keys())
    for key, validator in {**required, **optional}.items():
        if key in value:
            validator(value[key])


def info(value):
    object_fields(value, {
        "url": public_url, "listen_host": host, "listen_port": port,
        "input_fee_ppk": integer, "use_keyset_v2": choice(True),
        "http_cache": lambda row: object_fields(row, {"backend": choice("memory")}),
        "logging": lambda row: object_fields(row, {
            "output": choice("stderr"), "format": choice("json"),
            "console_level": choice("debug", "info", "warn", "error"),
        }),
    }, {
        "mnemonic": secret_reference, "seed": secret_reference,
        "quote_ttl": lambda row: object_fields(row, {"mint_ttl": positive, "melt_ttl": positive}),
    })
    require(("mnemonic" in value) != ("seed" in value))


def database(value):
    object_fields(value, {"engine": choice("sqlite", "postgres")}, {
        "postgres": lambda row: object_fields(row, {
            "url": secret_reference, "tls_mode": choice("disable", "verify-full"),
            "max_connections": positive, "connection_timeout_seconds": positive,
        }),
    })
    require((value["engine"] == "postgres") == ("postgres" in value))


def single_row(value, fields):
    require(type(value) is list and len(value) == 1)
    object_fields(value[0], fields)


def mint_info(value):
    object_fields(value, {
        "ctf_default_keyset_creation": choice("none", "one-vs-rest", "all"),
        "ctf_registration_fees": lambda rows: single_row(rows, {
            "unit": choice("msat"), "registration_fee_base": integer,
            "registration_fee_per_keyset": integer,
        }),
        "ctf_settlement": lambda row: object_fields(row, {
            key: positive for key in ("max_participants", "max_inputs", "max_outputs",
                                     "max_request_bytes", "max_expiry_seconds", "max_pool_entries")
        }),
    }, {
        **{key: text for key in ("name", "description", "description_long", "motd",
                                "contact_nostr_public_key", "contact_email")},
        "pubkey": plain_text, "icon_url": public_url, "tos_url": public_url,
    })


def management(value):
    require(type(value) is dict and type(value.get("enabled")) is bool)
    if not value["enabled"]:
        object_fields(value, {"enabled": choice(False)})
        return
    object_fields(value, {
        "enabled": choice(True), "address": host, "port": port, "tls_dir": absolute_path,
        "strict_tls": choice(True), "allow_insecure": choice(False),
        "allow_mint_quote_payment_override": choice(False),
        "expected_client_dns_name": host, "expected_client_spki_pin_path": absolute_path,
    })


def validate_input(value):
    object_fields(value, {"environment": choice("local", "staging"), "settings": lambda _: None})
    settings = value["settings"]
    object_fields(settings, {
        "info": info, "database": database,
        "payment_backend": lambda rows: single_row(rows, {
            "backend": choice("fakewallet"), "unit": choice("msat"),
            "min_mint": integer, "max_mint": positive, "min_melt": integer, "max_melt": positive,
        }),
        "fake_wallet": lambda row: object_fields(row, {}),
        "limits": lambda row: object_fields(row, {"max_inputs": positive, "max_outputs": positive},
                                            {"max_outcomes_per_condition": positive}),
        "mint_info": mint_info, "mint_management_rpc": management,
    })
    mint_url = urlsplit(settings["info"]["url"])
    require(mint_url.path in ("", "/"))
    if value["environment"] == "staging":
        require(mint_url.scheme == "https")
        require(settings["database"]["engine"] == "postgres")
        require(settings["database"]["postgres"]["tls_mode"] == "verify-full")
        require(settings["info"]["logging"]["console_level"] == "info")
    elif mint_url.scheme == "http":
        require(mint_url.hostname in ("localhost", "127.0.0.1", "::1"))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def refuse_number(_):
    raise InputRefused("input refused")


def parse_input(raw):
    require(type(raw) is bytes and len(raw) <= MAX_INPUT_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_float=refuse_number, parse_constant=refuse_number)
        validate_input(value)
    except (ValueError, UnicodeError, RecursionError):
        raise InputRefused("input refused") from None
    return value


def scalar(value):
    if type(value) is str:
        # JSON basic-string escapes are valid TOML escapes. TOML also forbids DEL.
        return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")
    if type(value) is bool:
        return "true" if value else "false"
    return str(value)


def render_document(value):
    validate_input(value)
    lines = []

    def table(path, fields, array=False):
        brackets = ("[[", "]]") if array else ("[", "]")
        lines.append(brackets[0] + path + brackets[1])
        for key in sorted(fields):
            child = fields[key]
            if type(child) in (str, int, bool):
                lines.append(key + " = " + scalar(child))
        lines.append("")
        for key in sorted(fields):
            child = fields[key]
            if type(child) is dict:
                table(path + "." + key, child)
            elif type(child) is list:
                for row in child:
                    table(path + "." + key, row, array=True)

    for key in sorted(value["settings"]):
        child = value["settings"][key]
        if type(child) is list:
            for row in child:
                table(key, row, array=True)
        else:
            table(key, child)
    return "\n".join(lines)


def write_document(destination, document, *, overwrite=False):
    """Publish a complete file. The caller must own the parent directory."""
    destination = Path(destination)
    try:
        mode = destination.lstat().st_mode
    except FileNotFoundError:
        mode = None
    if mode is not None:
        if not overwrite:
            raise FileExistsError("output exists")
        if not stat.S_ISREG(mode):
            raise OSError("output is not a regular file")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, prefix=".mint-config-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            # An atomic hard link gives no-clobber semantics without a check/use race.
            os.link(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise InputRefused("arguments refused")


def main(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--overwrite", action="store_true")
    try:
        args = parser.parse_args(argv)
        require(args.input.resolve() != args.output.resolve())
        if args.output.exists():
            require(not args.input.samefile(args.output))
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        document = render_document(parse_input(raw))
        write_document(args.output, document, overwrite=args.overwrite)
    except InputRefused:
        print("Mint configuration input refused.", file=sys.stderr)
        return 64
    except (OSError, UnicodeError):
        print("Mint configuration file operation failed.", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
