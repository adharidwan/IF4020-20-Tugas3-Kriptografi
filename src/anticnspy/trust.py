from pathlib import Path

from .errors import FormatError, InputError
from .formats import (
    HEX_PATTERN,
    PACKAGE_PATTERN,
    PROFILES,
    TRUST_SCHEMA,
    document_bytes,
    exact_fields,
    parse_json,
    text,
)
from .keys import KEY_LIMIT, fingerprint, load_public, profile, public_bytes
from .storage import atomic_write, read_bytes, require_distinct


def empty_store() -> dict:
    return {"schema": TRUST_SCHEMA, "keys": []}


def validate_store(store) -> dict:
    exact_fields(store, ("schema", "keys"), "trust store")
    if store["schema"] != TRUST_SCHEMA or type(store["keys"]) is not list:
        raise FormatError("Invalid trust store schema or keys array.")
    seen = set()
    for entry in store["keys"]:
        exact_fields(entry, ("keyid", "algorithm", "public_key_pem", "packages"), "trust key")
        keyid = text(entry["keyid"], "trust keyid", HEX_PATTERN)
        if keyid in seen:
            raise FormatError("Duplicate trust keyid.")
        seen.add(keyid)
        if type(entry["algorithm"]) is not str or entry["algorithm"] not in PROFILES:
            raise FormatError("Unsupported trust-key profile.")
        pem = text(entry["public_key_pem"], "public_key_pem")
        key = load_public(pem.encode("ascii"))
        if profile(key) != entry["algorithm"] or fingerprint(key) != keyid:
            raise FormatError("Trust-key profile or fingerprint does not match its public key.")
        packages = entry["packages"]
        if type(packages) is not list or not packages:
            raise FormatError("Trust-key packages must be a nonempty array.")
        for package in packages:
            text(package, "permitted package", PACKAGE_PATTERN)
        if len(set(packages)) != len(packages):
            raise FormatError("Duplicate package permission.")
    return store


def parse_store(raw: bytes) -> dict:
    return validate_store(parse_json(raw, "trust store"))


def add(key_path: str | Path, package: str, store_path: str | Path) -> dict:
    text(package, "package", PACKAGE_PATTERN)
    require_distinct(store_path, key_path)
    key = load_public(read_bytes(key_path, KEY_LIMIT))
    keyid = fingerprint(key)
    try:
        store = parse_store(read_bytes(store_path))
    except FileNotFoundError:
        store = empty_store()
    entry = next((item for item in store["keys"] if item["keyid"] == keyid), None)
    if entry is None:
        entry = {
            "keyid": keyid,
            "algorithm": profile(key),
            "public_key_pem": public_bytes(key).decode("ascii"),
            "packages": [package],
        }
        store["keys"].append(entry)
    elif package in entry["packages"]:
        return entry
    else:
        entry["packages"].append(package)
    atomic_write(store_path, document_bytes(store), overwrite=True)
    return entry


def list_keys(store_path: str | Path) -> list[dict]:
    return parse_store(read_bytes(store_path))["keys"]


def remove(keyid: str, store_path: str | Path) -> None:
    text(keyid, "keyid", HEX_PATTERN)
    store = parse_store(read_bytes(store_path))
    remaining = [entry for entry in store["keys"] if entry["keyid"] != keyid]
    if len(remaining) == len(store["keys"]):
        raise InputError("Key ID not found in trust store.")
    store["keys"] = remaining
    atomic_write(store_path, document_bytes(store), overwrite=True)
