from pathlib import Path

from . import crypto
from .artifacts import inspect_stream, open_artifact
from .errors import FormatError, InputError
from .formats import BUNDLE_LIMIT, PROFILES, parse_bundle, parse_manifest, validate_metadata
from .keys import load_public
from .results import Status, VerificationResult, result
from .storage import read_bytes
from .trust import parse_store


def verify_file(
    file: str | Path, bundle: str | Path, trust_store: str | Path, package: str, version: str
) -> VerificationResult:
    manifest = None
    try:
        try:
            validate_metadata(package, version)
        except FormatError as exc:
            raise InputError(str(exc)) from exc

        with open_artifact(file) as stream:
            bundle_raw = read_bytes(bundle, BUNDLE_LIMIT)
            trust_raw = read_bytes(trust_store)
            try:
                message, signature = parse_bundle(bundle_raw)
                manifest = parse_manifest(message)
                store = parse_store(trust_raw)
            except FormatError as exc:
                return result(Status.FORMAT_ERROR, str(exc), manifest)
            algorithm = manifest["algorithm"]
            if algorithm not in PROFILES:
                return result(
                    Status.UNSUPPORTED_ALGORITHM, "Unsupported manifest algorithm.", manifest
                )
            entry = next(
                (item for item in store["keys"] if item["keyid"] == manifest["keyid"]), None
            )
            if entry is None or entry["algorithm"] != algorithm or package not in entry["packages"]:
                return result(
                    Status.KEY_NOT_TRUSTED, "Signer is not trusted for this package.", manifest
                )
            key = load_public(entry["public_key_pem"].encode("ascii"))
            if not crypto.verify(key, message, signature):
                return result(Status.INVALID_SIGNATURE, "Manifest signature is invalid.", manifest)
            if (
                manifest["package"] != package
                or manifest["version"] != version
                or manifest["artifact"]["name"] != Path(file).name
            ):
                return result(
                    Status.METADATA_MISMATCH, "Release metadata or filename differs.", manifest
                )
            size, digest = inspect_stream(stream)
            if size != manifest["artifact"]["size"] or digest != manifest["artifact"]["sha256"]:
                return result(
                    Status.ARTIFACT_MISMATCH, "Artifact size or SHA-256 differs.", manifest
                )
            return result(
                Status.OK, "Signature, trust, metadata, and artifact are valid.", manifest
            )
    except (OSError, InputError) as exc:
        return result(Status.INPUT_ERROR, str(exc), manifest)
