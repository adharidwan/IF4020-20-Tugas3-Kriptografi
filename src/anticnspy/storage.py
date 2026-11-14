import os
import tempfile
from pathlib import Path

from .errors import InputError


def read_bytes(path: str | Path, limit: int | None = None) -> bytes:
    with open(path, "rb") as stream:
        return stream.read() if limit is None else stream.read(limit + 1)


def atomic_write(path: str | Path, data: bytes, *, overwrite: bool, mode: int = 0o644) -> None:

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            if os.name == "posix":
                os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, target)
        else:
            try:
                os.link(temporary, target)
            except FileExistsError as exc:
                raise InputError(
                    f"Output already exists: {target}. Use --force to overwrite."
                ) from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def require_distinct(output: str | Path, *inputs: str | Path) -> None:
    target = Path(output).resolve()
    for source in inputs:
        other = Path(source).resolve()
        if target == other or (
            target.exists() and other.exists() and os.path.samefile(target, other)
        ):
            raise InputError("Output must not overwrite an input file.")
