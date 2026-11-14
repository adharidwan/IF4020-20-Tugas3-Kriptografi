from pathlib import Path

from . import crypto
from .artifacts import inspect_stream, open_artifact
from .formats import (
    MANIFEST_SCHEMA,
    NAME_PATTERN,
    document_bytes,
    make_bundle,
    serialize_manifest,
    text,
    validate_metadata,
)
from .keys import KEY_LIMIT, fingerprint, load_private, profile
from .storage import atomic_write, read_bytes, require_distinct


def sign_file(
    file: str | Path,
    package: str,
    version: str,
    key: str | Path,
    out: str | Path,
    *,
    force: bool = False,
) -> dict:
    validate_metadata(package, version)
    require_distinct(out, file, key)
    name = text(Path(file).name, "artifact.name", NAME_PATTERN)
    private_key = load_private(read_bytes(key, KEY_LIMIT))
    with open_artifact(file) as stream:
        size, digest = inspect_stream(stream)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "package": package,
        "version": version,
        "algorithm": profile(private_key),
        "keyid": fingerprint(private_key.public_key()),
        "artifact": {"name": name, "size": size, "sha256": digest},
    }
    message = serialize_manifest(manifest)
    signature = crypto.sign(private_key, message)
    atomic_write(out, document_bytes(make_bundle(message, signature)), overwrite=force)
    return manifest
