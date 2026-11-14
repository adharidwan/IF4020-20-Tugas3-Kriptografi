import argparse
from pathlib import Path

from anticnspy import trust
from anticnspy.formats import PROFILES
from anticnspy.keys import keygen

SECRET_NAMES = {
    "rsa-pss-sha256": "DEMO_RSA_PRIVATE_KEY",
    "ecdsa-p256-sha256": "DEMO_ECDSA_PRIVATE_KEY",
    "ed25519": "DEMO_ED25519_PRIVATE_KEY",
}


def main():
    parser = argparse.ArgumentParser(
        description=(
            "One-time, explicit demo publisher provisioning, outside the consumer pipeline.\n\n"
            "Private keys are written to --keys-dir, which must remain private and separate\n"
            "from committed ci/trust public stores. Install their PEM values as CI secrets.\n"
        )
    )
    parser.add_argument("--keys-dir", type=Path, required=True)
    parser.add_argument("--trust-dir", type=Path, default=Path("ci/trust"))
    args = parser.parse_args()
    key_root, trust_root = args.keys_dir.resolve(), args.trust_dir.resolve()
    if (
        key_root == trust_root
        or key_root.is_relative_to(trust_root)
        or trust_root.is_relative_to(key_root)
    ):
        parser.error("Keep private keys and public trust stores in separate directories.")
    if any((key_root / f"{algorithm}.key.pem").exists() for algorithm in PROFILES):
        parser.error("Demo key already exists. Provision a new directory or use its existing keys.")
    for algorithm in PROFILES:
        prefix = key_root / algorithm
        generated = keygen(algorithm, prefix)
        entry = trust.add(f"{prefix}.pub.pem", "anticnspy-demo", trust_root / f"{algorithm}.json")
        print(
            f"{algorithm}: fingerprint {entry['keyid']}; CI secret {SECRET_NAMES[algorithm]}; "
            f"private file {generated['private_key']}"
        )


if __name__ == "__main__":
    main()
