from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import ROOT, build_manifest, review_inputs
from scripts.audit_artifacts import check_body_hash
from scripts import review_ledger
from scripts.review_ledger import append, load


class ReviewLedgerCommitTests(unittest.TestCase):
    def _records(self) -> tuple[dict, dict, dict, dict, set[str], dict, dict]:
        registry, _, _, manifest = build_manifest()
        screen, domain_context, _ = review_inputs(manifest)
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        base = {
            "record_type": "review",
            "schema_version": 7,
            "canonical_id": entry["canonical_id"],
            "owner_domain": entry["owner_domain"],
            "check_body_hash": check_body_hash(check),
            "evidence": [{"kind": "manual", "location": "fixture", "reason": "review"}],
        }
        suspicious = {**base, "review_stage": "DEEP_REVIEW", "status": "SUSPICIOUS", "code_path": "entry", "unresolved_reason": "proof pending"}
        proof = {
            **base,
            "review_stage": "PROOF",
            "status": "REVIEWED_SAFE",
            "applicability": "APPLICABLE - guard",
            "code_path": "entry",
            "preserved_invariant": "invariant holds",
        }
        return registry, manifest, screen, domain_context, {entry["canonical_id"]}, suspicious, proof

    def test_commit_sidecar_binds_authoritative_prefix_and_ignores_tail(self) -> None:
        registry, manifest, screen, domain_context, expected_ids, suspicious, _ = self._records()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.jsonl"
            append(path, manifest, suspicious, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            sidecar = Path(f"{path}.commit.json")
            metadata = json.loads(sidecar.read_text(encoding="utf-8"))
            committed = path.read_bytes()
            self.assertEqual(metadata["committed_bytes"], len(committed))
            self.assertEqual(metadata["prefix_sha256"], hashlib.sha256(committed).hexdigest())
            path.write_bytes(committed + b'{"record_type":"review"')
            self.assertEqual(len(load(path)), 2)
            self.assertEqual(json.loads(sidecar.read_text(encoding="utf-8")), metadata)

    def test_ledger_content_digest_binds_committed_state(self) -> None:
        registry, manifest, screen, domain_context, expected_ids, suspicious, proof = self._records()
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "review-a.jsonl"
            second = Path(directory) / "review-b.jsonl"
            append(first, manifest, suspicious, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            before = review_ledger.ledger_content_digest([first, second])
            self.assertEqual(review_ledger.ledger_content_digest([second, first]), before)

            append(first, manifest, proof, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            after_append = review_ledger.ledger_content_digest([first, second])
            self.assertNotEqual(after_append, before)

            # uncommitted tail bytes are not part of the authoritative content
            committed = first.read_bytes()
            first.write_bytes(committed + b'{"record_type":"review"')
            self.assertEqual(review_ledger.ledger_content_digest([first, second]), after_append)

            # identical content under a different ledger name is a different
            # ledger state, so the name participates in the digest
            second.write_bytes(committed)
            second.with_name(f"{second.name}.commit.json").write_bytes(
                first.with_name(f"{first.name}.commit.json").read_bytes()
            )
            self.assertNotEqual(
                review_ledger.ledger_content_digest([second]),
                review_ledger.ledger_content_digest([first]),
            )

    def test_short_write_and_sidecar_failure_never_commit_new_tail(self) -> None:
        registry, manifest, screen, domain_context, expected_ids, suspicious, proof = self._records()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.jsonl"
            append(path, manifest, suspicious, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            committed = path.read_bytes()
            original_write = review_ledger.os.write

            def short_then_fail(fd: int, data: bytes) -> int:
                original_write(fd, data[: max(1, len(data) // 2)])
                raise OSError("injected short write failure")

            with patch.object(review_ledger.os, "write", side_effect=short_then_fail):
                with self.assertRaisesRegex(OSError, "short write failure"):
                    append(path, manifest, proof, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            self.assertEqual(load(path), [json.loads(line) for line in committed.decode().splitlines()])
            path.write_bytes(committed)

            with patch.object(review_ledger.os, "fsync", side_effect=OSError("before fsync")):
                with self.assertRaisesRegex(OSError, "before fsync"):
                    append(path, manifest, proof, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            self.assertEqual(load(path), [json.loads(line) for line in committed.decode().splitlines()])
            path.write_bytes(committed)

            with patch.object(review_ledger, "_publish_commit", side_effect=OSError("before sidecar")):
                with self.assertRaisesRegex(OSError, "before sidecar"):
                    append(path, manifest, proof, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            self.assertEqual(load(path), [json.loads(line) for line in committed.decode().splitlines()])

    def test_truncated_or_tampered_committed_prefix_fails_closed(self) -> None:
        registry, manifest, screen, domain_context, expected_ids, suspicious, _ = self._records()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.jsonl"
            append(path, manifest, suspicious, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            sidecar = Path(f"{path}.commit.json")
            metadata = json.loads(sidecar.read_text(encoding="utf-8"))
            committed = path.read_bytes()
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, "shorter than its committed prefix"):
                load(path)
            path.write_bytes(committed)
            path.write_bytes(b"x" * (metadata["committed_bytes"] - 1) + b"\n")
            with self.assertRaisesRegex(ValueError, "prefix hash mismatch"):
                load(path)

    def test_legacy_ledger_gets_sidecar_on_next_successful_append(self) -> None:
        registry, manifest, screen, domain_context, expected_ids, suspicious, proof = self._records()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.jsonl"
            append(path, manifest, suspicious, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            sidecar = Path(f"{path}.commit.json")
            sidecar.unlink()
            self.assertEqual(len(load(path)), 2)
            append(path, manifest, proof, registry, expected_ids, domain_context=domain_context, screen_results=screen)
            self.assertTrue(sidecar.exists())
            self.assertEqual(len(load(path)), 3)


if __name__ == "__main__":
    unittest.main()
