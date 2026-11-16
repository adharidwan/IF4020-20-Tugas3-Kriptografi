"""Signed SBOM: a CycloneDX JSON file that records the SHA-256 of one release artifact.

The SBOM is signed like any other file, so its bundle uses the normal
minisign-bundle/v1 format and the normal trust store.
"""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from .artifacts import inspect_stream, open_artifact
from .errors import FormatError, InputError
from .formats import (
    BUNDLE_LIMIT,
    HEX_PATTERN,
    MAX_ARTIFACT_SIZE,
    NAME_PATTERN,
    VERSION_PATTERN,
    parse_bundle,
    parse_json,
    parse_manifest,
    text,
    validate_metadata,
)
from .results import Status, VerificationResult
from .signing import sign_file
from .storage import atomic_write, read_bytes, require_distinct
from .verification import verify_file

SBOM_LIMIT = 1024 * 1024
BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.6"
NAME_PROPERTY = "anticnspy:artifact.name"
SIZE_PROPERTY = "anticnspy:artifact.size"


def _dependency(value: str) -> dict:
    name, sep, version = value.partition("==")
    if not sep:
        raise InputError(f"Dependency must be NAME==VERSION: {value!r}.")
    text(name, "dependency name", NAME_PATTERN)
    text(version, "dependency version", VERSION_PATTERN)
    return {"type": "library", "name": name, "version": version}


def create(
    file: str | Path,
    package: str,
    version: str,
    out: str | Path,
    *,
    dependencies: list[str] | None = None,
    force: bool = False,
) -> dict:
    """Write an SBOM for `file` and return it."""
    validate_metadata(package, version)
    require_distinct(out, file)
    name = text(Path(file).name, "artifact.name", NAME_PATTERN)
    with open_artifact(file) as stream:
        size, digest = inspect_stream(stream)
    sbom = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": package,
                "version": version,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": [
                    {"name": NAME_PROPERTY, "value": name},
                    {"name": SIZE_PROPERTY, "value": str(size)},
                ],
            }
        },
        "components": [_dependency(item) for item in dependencies or []],
    }
    raw = (json.dumps(sbom, ensure_ascii=True, indent=2) + "\n").encode()
    atomic_write(out, raw, overwrite=force)
    return sbom


def parse(raw: bytes) -> dict:
    """Read the release fields from an SBOM. Raise FormatError if they are not valid."""
    sbom = parse_json(raw, "SBOM", SBOM_LIMIT)
    if type(sbom) is not dict or sbom.get("bomFormat") != BOM_FORMAT:
        raise FormatError("SBOM must be a CycloneDX JSON document.")
    if sbom.get("specVersion") != SPEC_VERSION:
        raise FormatError(f"SBOM specVersion must be {SPEC_VERSION}.")
    component = (
        sbom.get("metadata", {}).get("component") if type(sbom.get("metadata")) is dict else None
    )
    if type(component) is not dict:
        raise FormatError("SBOM has no metadata.component.")
    hashes = component.get("hashes")
    if type(hashes) is not list:
        raise FormatError("SBOM component has no hashes.")
    sha = [
        item.get("content")
        for item in hashes
        if type(item) is dict and item.get("alg") == "SHA-256"
    ]
    if len(sha) != 1:
        raise FormatError("SBOM component must have exactly one SHA-256 hash.")
    properties = component.get("properties")
    if type(properties) is not list:
        raise FormatError("SBOM component has no properties.")
    values = {}
    for item in properties:
        if type(item) is dict and item.get("name") in (NAME_PROPERTY, SIZE_PROPERTY):
            if item["name"] in values:
                raise FormatError(f"Duplicate SBOM property {item['name']}.")
            values[item["name"]] = item.get("value")
    if set(values) != {NAME_PROPERTY, SIZE_PROPERTY}:
        raise FormatError("SBOM must record the artifact name and size.")
    size = text(values[SIZE_PROPERTY], "artifact size")
    if not size.isdigit() or str(int(size)) != size or int(size) > MAX_ARTIFACT_SIZE:
        raise FormatError("Invalid artifact size in SBOM.")
    release = {
        "package": component.get("name"),
        "version": component.get("version"),
        "name": values[NAME_PROPERTY],
        "size": int(size),
        "sha256": sha[0],
    }
    try:
        validate_metadata(release["package"], release["version"])
    except FormatError as exc:
        raise FormatError(f"Invalid SBOM component: {exc}") from exc
    text(release["name"], "artifact name", NAME_PATTERN)
    text(release["sha256"], "artifact SHA-256", HEX_PATTERN)
    return release


def _result(status: Status, message: str, release: dict | None = None) -> VerificationResult:
    release = release or {}
    return VerificationResult(
        status == Status.OK,
        str(status),
        message,
        package=release.get("package"),
        version=release.get("version"),
    )


def sign(
    sbom: str | Path,
    package: str,
    version: str,
    key: str | Path,
    out: str | Path,
    *,
    force: bool = False,
) -> dict:
    """Sign the SBOM file. The bundle has the same format as a release bundle."""
    release = parse(read_bytes(sbom, SBOM_LIMIT))
    if (release["package"], release["version"]) != (package, version):
        raise InputError("SBOM package or version differs from --package/--version.")
    return sign_file(sbom, package, version, key, out, force=force)


def _meta(checked: VerificationResult) -> tuple:
    return checked.algorithm, checked.keyid, checked.package, checked.version


def verify(
    sbom: str | Path, bundle: str | Path, trust_store: str | Path, package: str, version: str
) -> VerificationResult:
    """Verify the SBOM signature, then check that the SBOM describes package and version."""
    checked = verify_file(sbom, bundle, trust_store, package, version)
    if checked.status == Status.ARTIFACT_MISMATCH:
        return replace(checked, message="SBOM differs from the signed SBOM.")
    if not checked.valid:
        return checked
    meta = _meta(checked)
    try:
        raw = read_bytes(sbom, SBOM_LIMIT)
        signed = parse_manifest(parse_bundle(read_bytes(bundle, BUNDLE_LIMIT))[0])
        if hashlib.sha256(raw).hexdigest() != signed["artifact"]["sha256"]:
            return VerificationResult(
                False, str(Status.ARTIFACT_MISMATCH), "SBOM changed during verification.", *meta
            )
        release = parse(raw)
    except FormatError as exc:
        return VerificationResult(False, str(Status.FORMAT_ERROR), str(exc), *meta)
    except (OSError, InputError) as exc:
        return VerificationResult(False, str(Status.INPUT_ERROR), str(exc), *meta)
    if (release["package"], release["version"]) != (package, version):
        return VerificationResult(
            False, str(Status.METADATA_MISMATCH), "SBOM describes another release.", *meta
        )
    return VerificationResult(True, str(Status.OK), "SBOM signature is valid.", *meta)


def check(sbom: str | Path, file: str | Path) -> VerificationResult:
    """Check that `file` is the artifact that the SBOM describes (name, size and SHA-256)."""
    release = None
    try:
        with open_artifact(file) as stream:
            raw = read_bytes(sbom, SBOM_LIMIT)
            try:
                release = parse(raw)
            except FormatError as exc:
                return _result(Status.FORMAT_ERROR, str(exc))
            if release["name"] != Path(file).name:
                return _result(Status.METADATA_MISMATCH, "Artifact file name differs.", release)
            size, digest = inspect_stream(stream)
    except (OSError, InputError) as exc:
        return _result(Status.INPUT_ERROR, str(exc), release)
    if size != release["size"] or digest != release["sha256"]:
        return _result(Status.ARTIFACT_MISMATCH, "Artifact size or SHA-256 differs.", release)
    return _result(Status.OK, "Artifact matches the SBOM.", release)
