import copy
import json

import pytest

from anticnspy.errors import FormatError
from anticnspy.formats import decode_b64, parse_json, parse_manifest, serialize_manifest


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":{"b":1,"b":2}}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"\xef\xbb\xbf{}",
        b"\xff",
    ],
)
def test_strict_json(raw):
    with pytest.raises(FormatError):
        parse_json(raw, "test")


@pytest.mark.parametrize("value", ["YQ", "YQ===", "YR==", "YQ==\n", "Y Q==", "____", 0, None])
def test_strict_base64(value):
    with pytest.raises(FormatError):
        decode_b64(value, "test")


@pytest.mark.parametrize(
    "field,value",
    [
        ("size", True),
        ("size", 1.0),
        ("size", -1),
        ("size", 2**53),
        ("name", "../app"),
        ("sha256", "A" * 64),
    ],
)
def test_artifact_contract(release, field, value):
    manifest = copy.deepcopy(release()["manifest"])
    manifest["artifact"][field] = value
    with pytest.raises(FormatError):
        serialize_manifest(manifest)


@pytest.mark.parametrize(
    "field,value",
    [
        ("package", "App"),
        ("package", "a/b"),
        ("version", "1 0"),
        ("keyid", "a" * 63),
        ("algorithm", None),
    ],
)
def test_manifest_field_contract(release, field, value):
    manifest = copy.deepcopy(release()["manifest"])
    manifest[field] = value
    with pytest.raises(FormatError):
        serialize_manifest(manifest)


@pytest.mark.parametrize(
    "kind",
    ["extra", "missing", "nested_extra", "unicode_escape", "field_order", "integer_exponent"],
)
def test_manifest_must_be_exact_and_canonical(release, kind):
    manifest = copy.deepcopy(release()["manifest"])
    if kind == "extra":
        manifest["extra"] = 1
    elif kind == "missing":
        del manifest["keyid"]
    elif kind == "nested_extra":
        manifest["artifact"]["extra"] = 1
    elif kind == "field_order":
        manifest = dict(reversed(list(manifest.items())))
    raw = json.dumps(manifest, separators=(",", ":")).encode()
    if kind == "unicode_escape":
        raw = raw.replace(b'"app"', b'"\\u0061pp"')
    elif kind == "integer_exponent":
        size = str(manifest["artifact"]["size"]).encode()
        raw = raw.replace(b'"size":' + size, b'"size":1e0')
    with pytest.raises(FormatError):
        parse_manifest(raw)
