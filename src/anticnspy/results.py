from dataclasses import asdict, dataclass
from enum import StrEnum


class Status(StrEnum):
    INPUT_ERROR = "INPUT_ERROR"
    FORMAT_ERROR = "FORMAT_ERROR"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    METADATA_MISMATCH = "METADATA_MISMATCH"
    ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
    OK = "OK"


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    status: str
    message: str
    algorithm: str | None = None
    keyid: str | None = None
    package: str | None = None
    version: str | None = None

    @property
    def exit_code(self) -> int:
        if self.status == Status.OK:
            return 0
        return 2 if self.status == Status.INPUT_ERROR else 1

    def to_dict(self) -> dict:
        return asdict(self)


def result(status: Status, message: str, manifest: dict | None = None) -> VerificationResult:
    metadata = {}
    if manifest is not None:
        metadata = {
            field: manifest.get(field) if type(manifest.get(field)) is str else None
            for field in ("algorithm", "keyid", "package", "version")
        }
    return VerificationResult(status == Status.OK, str(status), message, **metadata)
