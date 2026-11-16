import argparse
import json
import sys

from . import __version__, sbom, trust
from .errors import FormatError, InputError
from .formats import PROFILES
from .keys import keygen
from .results import Status, result
from .signing import sign_file
from .verification import verify_file


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, allow_abbrev=False, **kwargs)

    def error(self, message):
        raise InputError(message)


def build_parser() -> Parser:
    parser = Parser(prog="anticnspy", description="AntiCNSpy software release signatures")
    parser.add_argument("--version", action="version", version=f"AntiCNSpy {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("keygen", help="Generate an exact-profile key pair")
    generate.add_argument("--algorithm", choices=PROFILES, required=True)
    generate.add_argument("--out", required=True, help="Output prefix (not a PEM filename)")
    generate.add_argument("--force", action="store_true", help="Explicitly overwrite key outputs")
    signing = commands.add_parser("sign", help="Sign a canonical release manifest")
    verifying = commands.add_parser("verify", help="Verify a release using explicit trust")
    for command in (signing, verifying):
        command.add_argument("--file", required=True)
        command.add_argument("--package", required=True)
        command.add_argument("--version", required=True, help="Expected release version")
    signing.add_argument("--key", required=True)
    signing.add_argument("--out", required=True)
    signing.add_argument("--force", action="store_true", help="Overwrite an existing bundle")
    verifying.add_argument("--bundle", required=True)
    verifying.add_argument("--trust-store", required=True)
    verifying.add_argument("--json", action="store_true", help="Emit one JSON result on stdout")
    managing = commands.add_parser("trust", help="Manage package-scoped public-key trust")
    operations = managing.add_subparsers(dest="operation", required=True)
    adding = operations.add_parser("add", help="Add an explicit package permission")
    adding.add_argument("--key", required=True)
    adding.add_argument("--package", required=True)
    listing = operations.add_parser("list", help="List trusted fingerprints and permissions")
    removing = operations.add_parser("remove", help="Remove a trusted key")
    removing.add_argument("--keyid", required=True)
    for command in (adding, listing, removing):
        command.add_argument("--store", required=True)
    bom = commands.add_parser("sbom", help="Create, sign and check a release SBOM")
    bom_ops = bom.add_subparsers(dest="operation", required=True)
    creating = bom_ops.add_parser("create", help="Write a CycloneDX SBOM for an artifact")
    creating.add_argument("--file", required=True)
    creating.add_argument("--package", required=True)
    creating.add_argument("--version", required=True)
    creating.add_argument("--out", required=True)
    creating.add_argument(
        "--dependency", action="append", default=[], help="NAME==VERSION (repeatable)"
    )
    creating.add_argument("--force", action="store_true", help="Overwrite an existing SBOM")
    bom_sign = bom_ops.add_parser("sign", help="Sign an SBOM into a separate bundle")
    bom_verify = bom_ops.add_parser("verify", help="Verify the SBOM signature")
    for command in (bom_sign, bom_verify):
        command.add_argument("--sbom", required=True)
        command.add_argument("--package", required=True)
        command.add_argument("--version", required=True)
    bom_sign.add_argument("--key", required=True)
    bom_sign.add_argument("--out", required=True)
    bom_sign.add_argument("--force", action="store_true", help="Overwrite an existing bundle")
    bom_verify.add_argument("--bundle", required=True)
    bom_verify.add_argument("--trust-store", required=True)
    bom_check = bom_ops.add_parser("check", help="Check that an artifact matches the SBOM")
    bom_check.add_argument("--sbom", required=True)
    bom_check.add_argument("--file", required=True)
    for command in (bom_verify, bom_check):
        command.add_argument("--json", action="store_true", help="Emit one JSON result on stdout")
    return parser


def _print_verification(checked, as_json: bool) -> int:
    if as_json:
        print(json.dumps(checked.to_dict(), ensure_ascii=True, separators=(",", ":")))
    else:
        print(f"{checked.status}: {checked.message}")
    if not checked.valid:
        print(f"{checked.status}: {checked.message}", file=sys.stderr)
    return checked.exit_code


def _run_sbom(args) -> int:
    if args.operation == "create":
        created = sbom.create(
            args.file,
            args.package,
            args.version,
            args.out,
            dependencies=args.dependency,
            force=args.force,
        )
        digest = created["metadata"]["component"]["hashes"][0]["content"]
        print(f"Wrote {args.out} for {args.file} (sha256 {digest})")
    elif args.operation == "sign":
        manifest = sbom.sign(
            args.sbom, args.package, args.version, args.key, args.out, force=args.force
        )
        print(f"Signed SBOM with {manifest['algorithm']} ({manifest['keyid']}); bundle: {args.out}")
    elif args.operation == "verify":
        checked = sbom.verify(args.sbom, args.bundle, args.trust_store, args.package, args.version)
        return _print_verification(checked, args.json)
    else:
        return _print_verification(sbom.check(args.sbom, args.file), args.json)
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    is_verify = arguments[:1] == ["verify"] or (
        arguments[:1] == ["sbom"] and arguments[1:2] in (["verify"], ["check"])
    )
    wants_json = is_verify and "--json" in arguments
    try:
        args = build_parser().parse_args(arguments)
        if args.command == "keygen":
            generated = keygen(args.algorithm, args.out, force=args.force)
            print(json.dumps(generated))
        elif args.command == "sign":
            manifest = sign_file(
                args.file, args.package, args.version, args.key, args.out, force=args.force
            )
            print(
                f"Signed {manifest['artifact']['name']} with {manifest['algorithm']} "
                f"({manifest['keyid']}); bundle: {args.out}"
            )
        elif args.command == "verify":
            checked = verify_file(
                args.file, args.bundle, args.trust_store, args.package, args.version
            )
            return _print_verification(checked, args.json)
        elif args.command == "sbom":
            return _run_sbom(args)
        elif args.operation == "add":
            entry = trust.add(args.key, args.package, args.store)
            print(json.dumps({field: entry[field] for field in ("keyid", "algorithm", "packages")}))
        elif args.operation == "list":
            entries = trust.list_keys(args.store)
            print(
                json.dumps(
                    [
                        {field: entry[field] for field in ("keyid", "algorithm", "packages")}
                        for entry in entries
                    ],
                    indent=2,
                )
            )
        else:
            trust.remove(args.keyid, args.store)
            print(f"Removed {args.keyid}.")
        return 0
    except (InputError, FormatError, OSError) as exc:
        if is_verify:
            return _print_verification(result(Status.INPUT_ERROR, str(exc)), wants_json)
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if is_verify:
            return _print_verification(result(Status.INPUT_ERROR, "Interrupted."), wants_json)
        print("INPUT_ERROR: Interrupted.", file=sys.stderr)
        return 2
