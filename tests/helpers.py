"""CLI runner and report writer helpers for veriseal black-box tests."""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path("tests/fixtures")
RESULTS_DIR = Path("tests/results")


def _rel(text: str) -> str:
    return text.replace(str(ROOT_DIR) + "/", "").replace(str(ROOT_DIR), ".")


@dataclass
class TestContext:
    work: Path
    trust_store: Path
    keyids: dict[str, str]
    text_file: Path
    bin_file: Path
    empty_file: Path
    base_zip: Path
    sbom_file: Path
    ref_prof: str
    ref_priv: Path
    ref_bundle: Path
    ref_b_obj: dict[str, Any]
    raw_m: bytes


def make_sbom_fixture(artifact_path: Path, pkg: str, ver: str) -> dict[str, Any]:
    data = artifact_path.read_bytes()
    sha = hashlib.sha256(data).hexdigest().lower()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "package": pkg,
        "version": ver,
        "artifact_sha256": sha,
        "artifact": {"name": artifact_path.name, "size": len(data), "sha256": sha},
        "subject": {"name": artifact_path.name, "sha256": sha},
        "metadata": {"component": {"name": pkg, "version": ver, "hashes": [{"alg": "SHA-256", "content": sha}]}},
        "components": [{"type": "library", "name": "cryptography", "version": "44.0.0"}],
    }


class CliRunner:
    def __init__(
        self,
        base_cmd: list[str],
        suite_cmd: str = "uv run python tests/run_tests.py",
        results_dir: Path = RESULTS_DIR,
    ) -> None:
        self.base_cmd = base_cmd
        self.suite_cmd = suite_cmd
        self.results_dir = results_dir
        self.records: list[dict[str, Any]] = []

    def invoke(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*self.base_cmd, *args],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            check=False,
        )

    def sign(self, file_p: Path, key_p: Path, out_p: Path, pkg: str = "contoh-app", ver: str = "1.0.0") -> int:
        return self.invoke(
            ["sign", "--file", str(file_p), "--package", pkg, "--version", ver, "--key", str(key_p), "--out", str(out_p)]
        ).returncode

    def check_verify(
        self,
        test_id: str,
        scenario: str,
        profile: str,
        file_p: Path,
        bundle_p: Path,
        trust_p: Path,
        expected_exit: int,
        expected_status: str,
        input_desc: str = "",
        pkg: str = "contoh-app",
        ver: str = "1.0.0",
        extra_passed: bool = True,
        extra_notes: str = "",
        custom_args: list[str] | None = None,
    ) -> bool:
        cmd_args = custom_args or [
            "verify",
            "--file", str(file_p),
            "--bundle", str(bundle_p),
            "--trust-store", str(trust_p),
            "--package", pkg,
            "--version", ver,
            "--json",
        ]
        proc = self.invoke(cmd_args)
        stdout_str = _rel(proc.stdout.strip())
        stderr_str = _rel(proc.stderr.strip())
        actual_status: str | None = None
        actual_valid: bool | None = None

        if stdout_str and len(stdout_str.splitlines()) == 1:
            try:
                parsed = json.loads(stdout_str)
                if isinstance(parsed, dict):
                    actual_status = parsed.get("status")
                    actual_valid = parsed.get("valid")
            except Exception:
                pass

        expected_valid = expected_status == "OK"
        passed = (
            proc.returncode == expected_exit
            and actual_status == expected_status
            and actual_valid is expected_valid
            and extra_passed
        )

        inputs_used = input_desc or _rel(str(file_p))
        self.records.append(
            {
                "id": test_id,
                "scenario": scenario,
                "profile": profile,
                "input_files": inputs_used,
                "command": _rel(" ".join(shlex.quote(x) for x in [*self.base_cmd, *cmd_args])),
                "expected": {"exit_code": expected_exit, "status": expected_status, "valid": expected_valid},
                "actual": {
                    "exit_code": proc.returncode,
                    "status": actual_status,
                    "valid": actual_valid,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                },
                "notes": extra_notes,
                "passed": passed,
            }
        )
        tag = "PASS" if passed else "FAIL"
        print(f"[{tag}] {test_id:<22} | {profile:<18} | exit={proc.returncode} (exp {expected_exit}) | status={actual_status}")
        return passed

    def write_reports(self) -> int:
        total = len(self.records)
        passed_count = sum(1 for r in self.records if r["passed"])
        target_cli = _rel(" ".join(self.base_cmd))
        (self.results_dir / "summary.json").write_text(
            json.dumps(
                {
                    "total": total,
                    "passed": passed_count,
                    "failed": total - passed_count,
                    "test_suite_command": self.suite_cmd,
                    "target_cli": target_cli,
                    "fixtures_dir": str(FIXTURES_DIR),
                    "results": self.records,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        md_lines = [
            "# Black-Box Security Test Results (`U01`–`U14` + `SBOM00`–`SBOM02`)",
            "",
            "## How to Run (Tata Cara Menjalankan Pengujian)",
            "",
            "```sh",
            "# Run against merged veriseal CLI:",
            "uv run python tests/run_tests.py",
            "",
            "# Run against standalone mock CLI (pre-merge dry run):",
            "uv run python tests/run_tests.py --mock",
            "```",
            "",
            "## Execution Metadata",
            "",
            f"- **Test Suite Command:** `{self.suite_cmd}`",
            f"- **Target CLI:** `{target_cli}`",
            f"- **Base Input Fixtures (`berkas masukan`):** `{FIXTURES_DIR}/` (`contoh-app.txt`, `contoh-app.bin`, `empty.dat`, `contoh-app.zip`, `sbom.json`)",
            f"- **Passed:** `{passed_count} / {total}`",
            "",
            "## Complete Test Matrix & Results",
            "",
            "| ID | Profile | Input File(s) (`Berkas Masukan`) | Scenario | Expected (`Exit` / `Status` / `Valid`) | Actual (`Exit` / `Status` / `Valid`) | Result |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in self.records:
            exp = r["expected"]
            act = r["actual"]
            exp_s = f"`{exp['exit_code']}` / `{exp['status']}` / `{str(exp['valid']).lower()}`"
            act_s = f"`{act['exit_code']}` / `{act['status']}` / `{str(act['valid']).lower()}`"
            md_lines.append(
                f"| `{r['id']}` | `{r['profile']}` | `{r['input_files']}` | {r['scenario']} | {exp_s} | {act_s} | **{'PASS' if r['passed'] else 'FAIL'}** |"
            )
        (self.results_dir / "SUMMARY.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

        print("-" * 88)
        print(f"Summary: {passed_count}/{total} passed. Evidence saved to {self.results_dir}")
        return 0 if passed_count == total else 1
