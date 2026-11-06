"""CLI argument parsing and command routing."""

import argparse
import json
import sys

from veriseal import __version__
from veriseal.contracts import EXIT_INPUT_ERROR, PROFILES, Status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="veriseal")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen")
    p_keygen.add_argument("--algorithm", required=True, choices=PROFILES)
    p_keygen.add_argument("--out", required=True)
    p_keygen.add_argument("--force", action="store_true")

    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--file", required=True)
    p_sign.add_argument("--package", required=True)
    p_sign.add_argument("--version", required=True)
    p_sign.add_argument("--key", required=True)
    p_sign.add_argument("--out", required=True)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--file", required=True)
    p_verify.add_argument("--bundle", required=True)
    p_verify.add_argument("--trust-store", required=True)
    p_verify.add_argument("--package", required=True)
    p_verify.add_argument("--version", required=True)
    p_verify.add_argument("--json", action="store_true", dest="json_output")

    p_trust = sub.add_parser("trust")
    trust_sub = p_trust.add_subparsers(dest="trust_command", required=True)

    p_t_add = trust_sub.add_parser("add")
    p_t_add.add_argument("--key", required=True)
    p_t_add.add_argument("--package", required=True)
    p_t_add.add_argument("--store", required=True)

    p_t_list = trust_sub.add_parser("list")
    p_t_list.add_argument("--store", required=True)

    p_t_rm = trust_sub.add_parser("remove")
    p_t_rm.add_argument("--keyid", required=True)
    p_t_rm.add_argument("--store", required=True)

    p_sbom = sub.add_parser("sbom")
    sbom_sub = p_sbom.add_subparsers(dest="sbom_command", required=True)

    p_s_sign = sbom_sub.add_parser("sign")
    p_s_sign.add_argument("--file", required=True)
    p_s_sign.add_argument("--artifact", required=True)
    p_s_sign.add_argument("--package", required=True)
    p_s_sign.add_argument("--version", required=True)
    p_s_sign.add_argument("--key", required=True)
    p_s_sign.add_argument("--out", required=True)

    p_s_verify = sbom_sub.add_parser("verify")
    p_s_verify.add_argument("--file", required=True)
    p_s_verify.add_argument("--bundle", required=True)
    p_s_verify.add_argument("--artifact", required=True)
    p_s_verify.add_argument("--artifact-bundle", required=True)
    p_s_verify.add_argument("--trust-store", required=True)
    p_s_verify.add_argument("--package", required=True)
    p_s_verify.add_argument("--version", required=True)
    p_s_verify.add_argument("--json", action="store_true", dest="json_output")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "json_output", False):
        print(
            json.dumps(
                {
                    "valid": False,
                    "status": Status.INPUT_ERROR,
                    "message": "Not implemented",
                    "algorithm": None,
                    "keyid": None,
                    "package": None,
                    "version": None,
                }
            )
        )
    else:
        print("Not implemented", file=sys.stderr)
    return EXIT_INPUT_ERROR
