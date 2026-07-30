from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ppf.assessors import AnsibleAssessor, NormalizationContext
from ppf.execution import RawExecutionResult

DIGEST = "sha256:" + ("1" * 64)


def _ref(identifier: str) -> dict[str, str]:
    return {"id": identifier, "digest": DIGEST, "uri": f"artifact:{identifier}"}


def test_ansible_runner_json_events_are_normalized_without_native_ids(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-runner")
    if executable is None:
        pytest.skip("locked Ansible Runner development environment is unavailable")
    private = tmp_path / "private"
    project = private / "project"
    inventory = private / "inventory"
    project.mkdir(parents=True)
    inventory.mkdir()
    (inventory / "hosts").write_text(
        "localhost ansible_connection=local\n",
        encoding="utf-8",
    )
    (project / "probe.yml").write_text(
        """
- name: PPF probe
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Emit structured fact
      ansible.builtin.debug:
        msg: ppf
""".lstrip(),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            executable,
            "run",
            str(private),
            "-p",
            "probe.yml",
            "-i",
            str(inventory / "hosts"),
            "--ident",
            "ppf-test",
            "--json",
        ],
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    observations = AnsibleAssessor().normalize(
        RawExecutionResult(
            invocation_id="invoke-" + ("1" * 64),
            launch_state="launched",
            status="completed",
            exit_code=completed.returncode,
            signal=None,
            started_at="2026-07-29T12:00:00Z",
            completed_at="2026-07-29T12:00:01Z",
            duration_ms=1000,
            stdout=completed.stdout,
            stderr=completed.stderr,
        ),
        NormalizationContext(
            case={
                "id": "case-ansible",
                "claimRef": "HO-01",
                "subject": {"id": "environment"},
                "fixture": {"id": "localhost"},
                "probe": {"probeRef": "ansible-probe"},
            },
            execution_id="execution-ansible",
            stdout_ref=_ref("stdout"),
            stderr_ref=_ref("stderr"),
        ),
    )
    semantic = observations[0]["semanticPayload"]
    assert observations[0]["status"] == "passed"
    assert any(event["event"] == "runner_on_ok" for event in semantic["events"])
    assert "uuid" not in str(semantic)
    assert "created" not in str(semantic)
