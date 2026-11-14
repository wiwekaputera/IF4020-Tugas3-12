"""CLI argument parsing and command routing.

Commands (Tabel 2.7): ``keygen``, ``sign``, ``verify``, ``trust add|list|remove``
and the bonus ``sbom sign|verify``.

Output rules (Tabel 2.9 / 2.10):

* results go to stdout, errors and extra information go to stderr;
* ``verify --json`` prints exactly one JSON object followed by a newline;
* exit code 0 = success, 1 = verification rejected, 2 = usage/I/O error.

The sign and verify pipelines are exposed as :func:`sign_release` and
:func:`verify_release` so they can be reused (``sbom`` uses them).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from veriseal import __version__, crypto
from veriseal.contracts import (
    EXIT_INPUT_ERROR,
    EXIT_OK,
    EXIT_VERIFY_FAIL,
    PROFILES,
    Status,
)
from veriseal.formats import (
    ARTIFACT_NAME_RE,
    MAX_ARTIFACT_SIZE,
    MAX_BUNDLE_BYTES,
    MAX_MANIFEST_BYTES,
    PACKAGE_RE,
    VERSION_RE,
    FormatError,
    atomic_write,
    build_bundle,
    build_manifest,
    hash_file,
    matches,
    parse_bundle,
    parse_manifest,
    read_limited,
    serialize_manifest,
)
from veriseal.trust import (
    TrustEntry,
    TrustStore,
    add_key,
    load_trust_store,
    remove_key,
    save_trust_store,
    store_exists,
)


class CliError(Exception):
    """A user-facing failure of a non-verify command (exit code 2)."""


class _UsageError(Exception):
    def __init__(self, usage: str, message: str) -> None:
        super().__init__(message)
        self.usage = usage


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that raises instead of exiting, so ``verify --json`` can
    still emit a JSON ``INPUT_ERROR`` result on a usage error."""

    def error(self, message: str):  # type: ignore[override]
        raise _UsageError(self.format_usage(), message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="veriseal")
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


# ---------------------------------------------------------------------------
# Verification result (Tabel 2.9)
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    """Outcome of a verification, serializable as Tabel 2.9.

    ``algorithm``/``keyid``/``package``/``version`` are only filled once the
    manifest has been parsed successfully; otherwise they stay ``None`` and
    are emitted as JSON ``null``. ``manifest`` is kept for internal callers
    (e.g. SBOM binding) and is not part of the JSON output.
    """

    status: str
    message: str
    algorithm: str | None = None
    keyid: str | None = None
    package: str | None = None
    version: str | None = None
    manifest: dict[str, Any] | None = field(default=None, repr=False)

    @property
    def valid(self) -> bool:
        return self.status == Status.OK

    @property
    def exit_code(self) -> int:
        if self.status == Status.OK:
            return EXIT_OK
        if self.status == Status.INPUT_ERROR:
            return EXIT_INPUT_ERROR
        return EXIT_VERIFY_FAIL

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "status": self.status,
            "message": self.message,
            "algorithm": self.algorithm,
            "keyid": self.keyid,
            "package": self.package,
            "version": self.version,
        }

    def with_status(self, status: str, message: str) -> VerifyResult:
        """Return a copy with a new status/message, keeping manifest fields."""
        return VerifyResult(status, message, self.algorithm, self.keyid, self.package, self.version, self.manifest)


def emit_result(result: VerifyResult, json_output: bool) -> int:
    """Print a verification result and return its exit code."""
    if json_output:
        sys.stdout.write(json.dumps(result.to_dict()) + "\n")
        sys.stdout.flush()
        if not result.valid:
            print(f"veriseal: {result.status}: {result.message}", file=sys.stderr)
    elif result.valid:
        print(f"{result.status}: {result.message}")
    else:
        print(f"{result.status}: {result.message}", file=sys.stderr)
    return result.exit_code


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_pem(path: str, what: str) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        raise CliError(f"cannot read {what} {path!r}: {exc.strerror or exc}") from None
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise CliError(f"{what} {path!r} is not a PEM file") from None


def _inspect(pem: str, path: str, what: str) -> crypto.KeyInfo:
    try:
        return crypto.inspect_key(pem)
    except (ValueError, TypeError) as exc:
        raise CliError(f"{what} {path!r} is not a supported key: {exc}") from None


def _check_regex(value: str, pattern, what: str) -> None:
    if not matches(pattern, value):
        raise CliError(f"invalid {what}: {value!r}")


def _format_entry(entry: TrustEntry) -> str:
    return f"{entry.keyid}  {entry.algorithm}  {','.join(entry.packages)}"


# ---------------------------------------------------------------------------
# Sign (Algoritma 1)
# ---------------------------------------------------------------------------


def sign_release(file: str, package: str, version: str, key: str, out: str) -> dict[str, Any]:
    """Sign an artifact and write a ``minisign-bundle/v1`` file.

    Implements Algoritma 1: validate inputs, derive profile and keyid from
    the private key, hash the artifact, build and serialize the manifest,
    sign the manifest bytes and write the bundle.

    :param file: artifact path; its basename becomes ``artifact.name``.
    :param package: package name (``[a-z0-9][a-z0-9._-]{0,63}``).
    :param version: release version (``[A-Za-z0-9][A-Za-z0-9._+-]{0,63}``).
    :param key: path of the PKCS#8 private key PEM.
    :param out: bundle path; must not exist yet.
    :returns: the signed manifest dict.
    :raises CliError: on any input, key or I/O problem (exit code 2).

    Example::

        sign_release("dist/contoh-app.zip", "contoh-app", "1.0.0",
                     "keys/publisher.key.pem", "release.json")
    """
    # 1. ValidInputs(f, p, v, sk, o)
    _check_regex(package, PACKAGE_RE, "package name")
    _check_regex(version, VERSION_RE, "version")
    name = os.path.basename(file)
    if not matches(ARTIFACT_NAME_RE, name):
        raise CliError(f"artifact file name {name!r} does not match [A-Za-z0-9][A-Za-z0-9._-]{{0,127}}")
    if not os.path.isfile(file):
        raise CliError(f"artifact {file!r} does not exist or is not a regular file")
    if os.path.lexists(out):
        raise CliError(f"output {out!r} already exists; refusing to overwrite it")
    priv_pem = _read_pem(key, "private key")
    info = _inspect(priv_pem, key, "private key")
    if not info.is_private:
        raise CliError(f"{key!r} is a public key; sign needs the private key (.key.pem)")

    # 2-5. profile, keyid, artifact size and hash
    try:
        size, digest = hash_file(file)
    except OSError as exc:
        raise CliError(f"cannot read artifact {file!r}: {exc.strerror or exc}") from None
    if size > MAX_ARTIFACT_SIZE:
        raise CliError("artifact is larger than 2^53-1 bytes")

    # 6-9. manifest
    try:
        manifest = build_manifest(package, version, info.profile, info.keyid, name, size, digest)
    except FormatError as exc:
        raise CliError(f"cannot build manifest: {exc}") from None
    manifest_bytes = serialize_manifest(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise CliError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")

    # 10-12. sign, bundle, write
    try:
        signature = crypto.sign_bytes(priv_pem, manifest_bytes)
        bundle = build_bundle(manifest_bytes, signature)
    except (ValueError, TypeError) as exc:
        raise CliError(f"signing failed: {exc}") from None
    try:
        atomic_write(out, bundle)
    except OSError as exc:
        raise CliError(f"cannot write bundle {out!r}: {exc.strerror or exc}") from None
    return manifest


# ---------------------------------------------------------------------------
# Verify (Algoritma 2 / Tabel 2.8)
# ---------------------------------------------------------------------------


def _unreadable(path: str) -> str | None:
    """Return an error message if ``path`` is not a readable regular file."""
    if not os.path.isfile(path):
        return "does not exist or is not a regular file"
    try:
        with open(path, "rb"):
            pass
    except OSError as exc:
        return exc.strerror or str(exc)
    return None


def verify_release(file: str, bundle: str, trust_store: str, package: str, version: str) -> VerifyResult:
    """Verify an artifact against a bundle and a trust store.

    Runs the checks of Tabel 2.8 in order and stops at the first failure:
    INPUT_ERROR, FORMAT_ERROR, UNSUPPORTED_ALGORITHM, KEY_NOT_TRUSTED,
    INVALID_SIGNATURE, METADATA_MISMATCH, ARTIFACT_MISMATCH, then OK.

    Nothing is written to disk. The trust store is the only source of trust;
    no key is taken from the bundle.

    :param file: artifact path.
    :param bundle: bundle path.
    :param trust_store: trust store path.
    :param package: package name the user expects.
    :param version: version the user expects.
    :returns: a :class:`VerifyResult` (never raises for bad input).

    Example::

        r = verify_release("contoh-app.zip", "release.json", "trust.json",
                           "contoh-app", "1.0.0")
        assert r.status == "OK"
    """
    res = VerifyResult(Status.INPUT_ERROR, "")

    # 1. INPUT_ERROR: options and readable files
    if not matches(PACKAGE_RE, package):
        return res.with_status(Status.INPUT_ERROR, f"invalid --package value: {package!r}")
    if not matches(VERSION_RE, version):
        return res.with_status(Status.INPUT_ERROR, f"invalid --version value: {version!r}")
    for what, path in (("artifact", file), ("bundle", bundle), ("trust store", trust_store)):
        problem = _unreadable(path)
        if problem:
            return res.with_status(Status.INPUT_ERROR, f"cannot read {what} {path!r}: {problem}")

    # 2. FORMAT_ERROR: bundle, manifest (canonical), trust store
    try:
        manifest_bytes, signature = parse_bundle(read_limited(bundle, MAX_BUNDLE_BYTES, "bundle"))
        manifest = parse_manifest(manifest_bytes)
    except OSError as exc:
        return res.with_status(Status.INPUT_ERROR, f"cannot read bundle {bundle!r}: {exc.strerror or exc}")
    except FormatError as exc:
        return res.with_status(Status.FORMAT_ERROR, str(exc))

    algorithm = manifest["algorithm"]
    keyid = manifest["keyid"]
    art = manifest["artifact"]
    res = VerifyResult(
        Status.INPUT_ERROR, "", algorithm, keyid, manifest["package"], manifest["version"], manifest
    )

    try:
        store: TrustStore = load_trust_store(trust_store)
    except OSError as exc:
        return res.with_status(Status.INPUT_ERROR, f"cannot read trust store {trust_store!r}: {exc.strerror or exc}")
    except FormatError as exc:
        return res.with_status(Status.FORMAT_ERROR, f"trust store: {exc}")

    # 3. UNSUPPORTED_ALGORITHM
    if algorithm not in PROFILES:
        return res.with_status(Status.UNSUPPORTED_ALGORITHM, f"unsupported algorithm {algorithm!r}")

    # 4. KEY_NOT_TRUSTED
    entry = store.lookup(keyid)
    if entry is None:
        return res.with_status(Status.KEY_NOT_TRUSTED, "keyid is not in the trust store")
    if entry.algorithm != algorithm:
        return res.with_status(
            Status.KEY_NOT_TRUSTED, f"trusted key is {entry.algorithm} but manifest says {algorithm}"
        )
    if package not in entry.packages:
        return res.with_status(Status.KEY_NOT_TRUSTED, f"key is not authorized for package {package!r}")

    # 5. INVALID_SIGNATURE (over the manifest bytes exactly as received)
    try:
        ok = crypto.verify_bytes(entry.public_key_pem, algorithm, manifest_bytes, signature)
    except (ValueError, TypeError):
        ok = False
    if not ok:
        return res.with_status(Status.INVALID_SIGNATURE, "signature does not verify with the trusted key")

    # 6. METADATA_MISMATCH
    if manifest["package"] != package:
        return res.with_status(
            Status.METADATA_MISMATCH, f"manifest package {manifest['package']!r} != expected {package!r}"
        )
    if manifest["version"] != version:
        return res.with_status(
            Status.METADATA_MISMATCH, f"manifest version {manifest['version']!r} != expected {version!r}"
        )
    name = os.path.basename(file)
    if art["name"] != name:
        return res.with_status(Status.METADATA_MISMATCH, f"manifest artifact name {art['name']!r} != file name {name!r}")

    # 7. ARTIFACT_MISMATCH
    try:
        size, digest = hash_file(file)
    except OSError as exc:
        return res.with_status(Status.INPUT_ERROR, f"cannot read artifact {file!r}: {exc.strerror or exc}")
    if size != art["size"]:
        return res.with_status(Status.ARTIFACT_MISMATCH, f"artifact size {size} != manifest size {art['size']}")
    if digest != art["sha256"]:
        return res.with_status(Status.ARTIFACT_MISMATCH, "artifact SHA-256 does not match the manifest")

    # 8. OK
    return res.with_status(Status.OK, "Signature and artifact are valid.")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    key_path = f"{args.out}.key.pem"
    pub_path = f"{args.out}.pub.pem"
    if not args.force:
        for path in (key_path, pub_path):
            if os.path.lexists(path):
                raise CliError(f"{path!r} already exists; use --force to overwrite")
    parent = os.path.dirname(os.path.abspath(key_path))
    try:
        os.makedirs(parent, exist_ok=True)
        priv_pem, pub_pem, keyid = crypto.generate_keypair(args.algorithm)
        atomic_write(key_path, priv_pem.encode("ascii"), mode=0o600)
        atomic_write(pub_path, pub_pem.encode("ascii"), mode=0o644)
    except OSError as exc:
        raise CliError(f"cannot write key files: {exc.strerror or exc}") from None
    print(f"private key: {key_path} (keep it secret)", file=sys.stderr)
    print(f"public key:  {pub_path}", file=sys.stderr)
    print(f"algorithm:   {args.algorithm}", file=sys.stderr)
    print(keyid)
    return EXIT_OK


def cmd_sign(args: argparse.Namespace) -> int:
    m = sign_release(args.file, args.package, args.version, args.key, args.out)
    print(f"signed {m['package']} {m['version']} ({m['algorithm']}, keyid {m['keyid']}) -> {args.out}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    result = verify_release(args.file, args.bundle, args.trust_store, args.package, args.version)
    return emit_result(result, args.json_output)


def _load_store_for_edit(path: str, create: bool) -> TrustStore:
    if not store_exists(path):
        if create:
            return TrustStore()
        raise CliError(f"trust store {path!r} does not exist")
    try:
        return load_trust_store(path)
    except OSError as exc:
        raise CliError(f"cannot read trust store {path!r}: {exc.strerror or exc}") from None
    except FormatError as exc:
        raise CliError(f"trust store {path!r} is invalid (left unchanged): {exc}") from None


def _save_store(path: str, store: TrustStore) -> None:
    try:
        save_trust_store(path, store)
    except OSError as exc:
        raise CliError(f"cannot write trust store {path!r}: {exc.strerror or exc}") from None


def cmd_trust_add(args: argparse.Namespace) -> int:
    _check_regex(args.package, PACKAGE_RE, "package name")
    pem = _read_pem(args.key, "public key")
    _inspect(pem, args.key, "public key")
    store = _load_store_for_edit(args.store, create=True)
    try:
        entry, changed = add_key(store, pem, args.package)
    except ValueError as exc:
        raise CliError(str(exc)) from None
    if changed:
        _save_store(args.store, store)
    else:
        print("already trusted for this package; trust store unchanged", file=sys.stderr)
    print(_format_entry(entry))
    return EXIT_OK


def cmd_trust_list(args: argparse.Namespace) -> int:
    store = _load_store_for_edit(args.store, create=False)
    if not store.keys:
        print("trust store is empty", file=sys.stderr)
    for entry in store.keys:
        print(_format_entry(entry))
    return EXIT_OK


def cmd_trust_remove(args: argparse.Namespace) -> int:
    store = _load_store_for_edit(args.store, create=False)
    try:
        entry = remove_key(store, args.keyid)
    except KeyError:
        raise CliError(f"keyid {args.keyid!r} is not in the trust store") from None
    _save_store(args.store, store)
    print(f"removed {_format_entry(entry)}")
    return EXIT_OK


def cmd_sbom_sign(args: argparse.Namespace) -> int:
    from veriseal import sbom

    m = sbom.sign_sbom(args.file, args.artifact, args.package, args.version, args.key, args.out)
    print(f"signed SBOM {m['artifact']['name']} for {m['package']} {m['version']} -> {args.out}")
    return EXIT_OK


def cmd_sbom_verify(args: argparse.Namespace) -> int:
    from veriseal import sbom

    result = sbom.verify_sbom(
        args.file,
        args.bundle,
        args.artifact,
        args.artifact_bundle,
        args.trust_store,
        args.package,
        args.version,
    )
    return emit_result(result, args.json_output)


_HANDLERS = {
    ("keygen", None): cmd_keygen,
    ("sign", None): cmd_sign,
    ("verify", None): cmd_verify,
    ("trust", "add"): cmd_trust_add,
    ("trust", "list"): cmd_trust_list,
    ("trust", "remove"): cmd_trust_remove,
    ("sbom", "sign"): cmd_sbom_sign,
    ("sbom", "verify"): cmd_sbom_verify,
}


def main(argv: list[str] | None = None) -> int:
    """Entry point of the ``veriseal`` executable. Returns the exit code."""
    if argv is None:
        argv = sys.argv[1:]
    wants_json = "--json" in argv and "verify" in argv
    try:
        args = build_parser().parse_args(argv)
    except _UsageError as exc:
        if wants_json:
            emit_result(VerifyResult(Status.INPUT_ERROR, f"usage error: {exc}"), True)
        else:
            sys.stderr.write(exc.usage)
        print(f"veriseal: error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    sub = getattr(args, "trust_command", None) or getattr(args, "sbom_command", None)
    handler = _HANDLERS[(args.command, sub)]
    try:
        return handler(args)
    except CliError as exc:
        print(f"veriseal: error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except Exception as exc:  # never leak a traceback or a misleading exit code
        msg = f"internal error: {type(exc).__name__}: {exc}"
        if getattr(args, "json_output", False):
            emit_result(VerifyResult(Status.INPUT_ERROR, msg), True)
        print(f"veriseal: {msg}", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
