import json

import pytest

from anticnspy.formats import PROFILES
from anticnspy.keys import generate, private_bytes, public_bytes
from anticnspy.signing import sign_file
from anticnspy.trust import add


@pytest.fixture(scope="session")
def key_material():
    material = {}
    for algorithm in PROFILES:
        key = generate(algorithm)
        material[algorithm] = (private_bytes(key), public_bytes(key.public_key()))
    return material


@pytest.fixture
def release(tmp_path, key_material):
    def make(algorithm="ed25519", content=b"release bytes\x00\xff\n"):
        directory = tmp_path / str(len(list(tmp_path.iterdir())))
        directory.mkdir()
        file = directory / "app.bin"
        secret = directory / "publisher.key.pem"
        public = directory / "publisher.pub.pem"
        bundle = directory / "release.json"
        store = directory / "trust.json"
        file.write_bytes(content)
        secret.write_bytes(key_material[algorithm][0])
        public.write_bytes(key_material[algorithm][1])
        entry = add(public, "app", store)
        manifest = sign_file(file, "app", "1.0.0", secret, bundle)
        return {
            "file": file,
            "key": secret,
            "public": public,
            "bundle": bundle,
            "store": store,
            "entry": entry,
            "manifest": manifest,
            "document": json.loads(bundle.read_bytes()),
        }

    return make
