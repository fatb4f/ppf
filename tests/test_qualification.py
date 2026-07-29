from __future__ import annotations

import json
from pathlib import Path

from qualification import EvidenceRecord, build_evidence, write_evidence


def test_qualification_evidence_is_complete_and_passing() -> None:
    records = build_evidence()
    assert len(records) == 9
    assert [record.check_id for record in records] == sorted(record.check_id for record in records)
    assert all(record.status == "pass" for record in records)


def test_qualification_jsonl_is_deterministic(tmp_path: Path) -> None:
    records = build_evidence()
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    write_evidence(reversed(records), first)
    write_evidence(records, second)
    assert first.read_bytes() == second.read_bytes()
    for line in first.read_text(encoding="utf-8").splitlines():
        payload = json.loads(line)
        assert EvidenceRecord.model_validate(payload)
        assert list(payload) == sorted(payload)
        assert not {"timestamp", "duration", "path", "temporary_directory"} & payload.keys()
