import base64
import binascii
import json
import re

from .errors import FormatError

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")
MANIFEST_SCHEMA = "minisign-manifest/v1"
BUNDLE_SCHEMA = "minisign-bundle/v1"
TRUST_SCHEMA = "minisign-trust/v1"
MANIFEST_LIMIT = 16 * 1024
BUNDLE_LIMIT = 64 * 1024
MAX_ARTIFACT_SIZE = 2**53 - 1
PACKAGE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}", re.ASCII)
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)
HEX_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
MANIFEST_FIELDS = ("schema", "package", "version", "algorithm", "keyid", "artifact")
ARTIFACT_FIELDS = ("name", "size", "sha256")


def _pairs(pairs: list[tuple]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise FormatError(f"Duplicate JSON field: {key!r}.")
        obj[key] = value
    return obj


def _constant(value: str):
    raise FormatError(f"Non-JSON number: {value}.")


def parse_json(raw: bytes, label: str, limit: int | None = None):
    if limit is not None and len(raw) > limit:
        raise FormatError(f"{label} exceeds {limit} bytes.")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise FormatError(f"{label} must not contain a UTF-8 BOM.")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, FormatError):
            raise
        raise FormatError(f"Invalid UTF-8 JSON in {label}.") from exc


def exact_fields(obj, fields, label: str) -> None:
    if type(obj) is not dict or set(obj) != set(fields):
        raise FormatError(f"{label} must contain exactly: {', '.join(fields)}.")


def text(value, label: str, pattern: re.Pattern | None = None) -> str:
    if type(value) is not str or not value.isascii():
        raise FormatError(f"{label} must be an ASCII string.")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise FormatError(f"Invalid {label}.")
    return value


def validate_metadata(package: str, version: str) -> None:
    text(package, "package", PACKAGE_PATTERN)
    text(version, "version", VERSION_PATTERN)


def validate_manifest(manifest) -> dict:
    exact_fields(manifest, MANIFEST_FIELDS, "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise FormatError("Unknown manifest schema.")
    validate_metadata(manifest["package"], manifest["version"])
    text(manifest["algorithm"], "algorithm")
    text(manifest["keyid"], "keyid", HEX_PATTERN)
    artifact = manifest["artifact"]
    exact_fields(artifact, ARTIFACT_FIELDS, "artifact")
    text(artifact["name"], "artifact.name", NAME_PATTERN)
    size = artifact["size"]
    if type(size) is not int or not 0 <= size <= MAX_ARTIFACT_SIZE:
        raise FormatError("artifact.size must be an integer in [0, 2^53 - 1].")
    text(artifact["sha256"], "artifact.sha256", HEX_PATTERN)
    return manifest


def serialize_manifest(manifest: dict) -> bytes:
    validate_manifest(manifest)
    ordered = {field: manifest[field] for field in MANIFEST_FIELDS}
    ordered["artifact"] = {field: manifest["artifact"][field] for field in ARTIFACT_FIELDS}
    raw = json.dumps(ordered, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MANIFEST_LIMIT:
        raise FormatError("Manifest exceeds 16 KiB.")
    return raw


def parse_manifest(raw: bytes) -> dict:
    manifest = validate_manifest(parse_json(raw, "manifest", MANIFEST_LIMIT))
    if serialize_manifest(manifest) != raw:
        raise FormatError("Manifest serialization is not canonical.")
    return manifest


def encode_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def decode_b64(value, label: str) -> bytes:
    text(value, label)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise FormatError(f"Invalid Base64 in {label}.") from exc
    if encode_b64(raw) != value:
        raise FormatError(f"Noncanonical Base64 in {label}.")
    return raw


def make_bundle(manifest_bytes: bytes, signature: bytes) -> dict:
    return {
        "schema": BUNDLE_SCHEMA,
        "manifest_b64": encode_b64(manifest_bytes),
        "signature_b64": encode_b64(signature),
    }


def parse_bundle(raw: bytes) -> tuple[bytes, bytes]:
    bundle = parse_json(raw, "bundle", BUNDLE_LIMIT)
    exact_fields(bundle, ("schema", "manifest_b64", "signature_b64"), "bundle")
    if bundle["schema"] != BUNDLE_SCHEMA:
        raise FormatError("Unknown bundle schema.")
    return (
        decode_b64(bundle["manifest_b64"], "manifest_b64"),
        decode_b64(bundle["signature_b64"], "signature_b64"),
    )


def document_bytes(document: dict) -> bytes:
    return (json.dumps(document, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode()
