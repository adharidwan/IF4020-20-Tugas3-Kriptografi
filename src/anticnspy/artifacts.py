import hashlib
import os
import stat
from pathlib import Path
from typing import BinaryIO

from .errors import InputError
from .formats import MAX_ARTIFACT_SIZE


def open_artifact(path: str | Path) -> BinaryIO:

    if not stat.S_ISREG(os.stat(path).st_mode):
        raise InputError("Artifact must be a regular file.")
    return open(path, "rb")


def inspect_stream(stream: BinaryIO) -> tuple[int, str]:
    before = os.fstat(stream.fileno())
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(1024 * 1024):
        size += len(chunk)
        digest.update(chunk)
    after = os.fstat(stream.fileno())
    if size > MAX_ARTIFACT_SIZE:
        raise InputError("Artifact exceeds the manifest size range.")
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise InputError("Artifact changed while being read.")
    return size, digest.hexdigest()
