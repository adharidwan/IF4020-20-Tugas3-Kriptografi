import shlex
from pathlib import Path

import pytest
import yaml

from anticnspy.formats import PROFILES
from anticnspy.signing import sign_file
from anticnspy.verification import verify_file

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("profile", PROFILES)
def test_container_ci_fixture_roundtrip(tmp_path, profile):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    step = next(
        step
        for step in workflow["jobs"]["container"]["steps"]
        if step.get("name") == "Local-image regression tests (not registry release evidence)"
    )
    command = shlex.split(step["run"])
    package = command[command.index("--package") + 1]
    artifact = ROOT / "test_cases/fixtures" / f"U01-{profile}-binary/app.bin"
    key = ROOT / "test_cases/keys" / f"{profile}.key.pem"
    store = artifact.with_name("trust.json")
    bundle = tmp_path / "release.json"
    sign_file(artifact, package, "1.0.0", key, bundle)

    checked = verify_file(artifact, bundle, store, package, "1.0.0")
    assert checked.status == "OK"
    assert checked.algorithm == profile
    assert checked.valid

    rejected = verify_file(artifact, bundle, store, "unpermitted-package", "1.0.0")
    assert rejected.status == "KEY_NOT_TRUSTED"
    assert not rejected.valid
