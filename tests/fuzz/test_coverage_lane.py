#!/usr/bin/env python3
"""Colocated tests for tests/fuzz/coverage_lane.py incident classification.

Covers the A5 lane incident taxonomy: harness/setup/infrastructure failures
(missing required seed corpus, FileNotFound, failed build, unexpected
non-crash exit) must classify as setup_* and never as validator_crash, while
``validator_crash`` is reserved for proven target-process crashes whose stack
touches production source (or whose input a deterministic standalone replay
confirms). Every incident JSON must carry the strict schema fields
(layer, taxonomy, repro_status, input_sha256, commit, toolchain, command,
stderr_tail, first_failing_frame).

Run: python tests/fuzz/test_coverage_lane.py
"""

import hashlib
import json
import os
import stat
import sys
import tempfile
import types
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
import coverage_lane  # noqa: E402

VALIDATOR_PANIC = (
    b"thread 42 panic: integer overflow\n"
    b"/repo/src/validate/arithmetic.zig:41:9: 0x000000000000 in add (safegguf)\n"
    b"/repo/tests/fuzz_target.zig:12:5: 0x000000000000 in fuzzOne (tests)\n"
)
ENGINE_PANIC = (
    b"thread 7 panic: fuzz worker failed\n"
    b"/opt/zig/lib/fuzzer.zig:120:5: 0x000000000000 in worker (fuzzer)\n"
    b"/opt/zig/lib/Build/Fuzz.zig:44:9: 0x000000000000 in run (fuzz)\n"
)
UNKNOWN_SEGV = b"Segmentation fault at address 0x0000000000000000\n"
FILE_NOT_FOUND = (
    b"run test: error: while executing test 'fuzz: gguf validator coverage "
    b"target', the test failed with error.FileNotFound\n"
)
BUILD_FAILURE = (
    b"/repo/build.zig:12:20: error: root struct of file 'fuzz_cov_target' has "
    b"no member named 'loadSeed'\n"
    b"error: the following command failed with 1 compilation errors:\n"
)
OOM_BLOB = b"error: OutOfMemory\npanic: out of memory\n"


class ClassifyIncidentTests(unittest.TestCase):
    def test_missing_required_corpus_is_setup_never_validator(self):
        taxonomy, _ = coverage_lane.classify_incident(
            b"", 1, required_corpus_present=False)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_SETUP_MISSING_CORPUS)
        self.assertTrue(taxonomy.startswith("setup_"))
        self.assertNotEqual(taxonomy, coverage_lane.TAXONOMY_VALIDATOR_CRASH)

    def test_missing_corpus_beats_crash_like_log_text(self):
        taxonomy, _ = coverage_lane.classify_incident(
            VALIDATOR_PANIC, 1, required_corpus_present=False)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_SETUP_MISSING_CORPUS)

    def test_file_not_found_is_setup(self):
        taxonomy, _ = coverage_lane.classify_incident(FILE_NOT_FOUND, 1)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_SETUP_FILE_NOT_FOUND)

    def test_build_failure_is_setup(self):
        taxonomy, _ = coverage_lane.classify_incident(BUILD_FAILURE, 1)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_SETUP_BUILD_FAILURE)

    def test_unexpected_non_crash_exit_is_setup_error(self):
        taxonomy, _ = coverage_lane.classify_incident(
            b"error: the following command exited with error code 1\n", 1)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_SETUP_ERROR)

    def test_setup_failures_are_never_validator_crash(self):
        cases = (
            (b"", 1, False),                # missing required corpus
            (FILE_NOT_FOUND, 1, True),      # FileNotFound
            (BUILD_FAILURE, 1, True),       # failed build
            (b"boom", 3, True),             # unexpected non-crash exit
        )
        for blob, rc, corpus_present in cases:
            taxonomy, _ = coverage_lane.classify_incident(blob, rc, corpus_present)
            self.assertIn(taxonomy, coverage_lane.SETUP_TAXONOMIES, (blob, rc))
            self.assertNotEqual(taxonomy, coverage_lane.TAXONOMY_VALIDATOR_CRASH)

    def test_production_panic_with_signal_is_validator_crash(self):
        taxonomy, site = coverage_lane.classify_incident(VALIDATOR_PANIC, -6)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_VALIDATOR_CRASH)
        self.assertEqual(site, "validator")

    def test_production_panic_with_nonzero_exit_is_validator_crash(self):
        taxonomy, site = coverage_lane.classify_incident(VALIDATOR_PANIC, 1)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_VALIDATOR_CRASH)
        self.assertEqual(site, "validator")

    def test_crash_log_with_clean_exit_is_not_validator_crash(self):
        # No signal and a zero exit: the crash is not proven, so the frames
        # alone must not produce a validator_crash.
        taxonomy, _ = coverage_lane.classify_incident(VALIDATOR_PANIC, 0)
        self.assertNotEqual(taxonomy, coverage_lane.TAXONOMY_VALIDATOR_CRASH)
        self.assertIn(taxonomy, coverage_lane.SETUP_TAXONOMIES)

    def test_engine_panic_is_engine_crash(self):
        taxonomy, site = coverage_lane.classify_incident(ENGINE_PANIC, -6)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_ENGINE_CRASH)
        self.assertEqual(site, "engine")

    def test_unknown_site_crash_is_unknown_crash(self):
        taxonomy, site = coverage_lane.classify_incident(UNKNOWN_SEGV, -11)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_UNKNOWN_CRASH)
        self.assertEqual(site, "unknown")

    def test_worker_crash_marker_with_nonzero_exit_is_proven(self):
        taxonomy, _ = coverage_lane.classify_incident(
            b"error: all fuzz workers crashed\n", 1)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_UNKNOWN_CRASH)

    def test_oom_marker_takes_precedence(self):
        taxonomy, _ = coverage_lane.classify_incident(VALIDATOR_PANIC + OOM_BLOB, -6)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_OOM)

    def test_fatal_build_toolchain_is_setup_not_crash(self):
        taxonomy, _ = coverage_lane.classify_incident(BUILD_FAILURE, -11)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_SETUP_BUILD_FAILURE)


class FirstFailingFrameTests(unittest.TestCase):
    def test_prefers_top_crash_frame(self):
        self.assertEqual(
            coverage_lane.first_failing_frame(VALIDATOR_PANIC),
            "/repo/src/validate/arithmetic.zig:41:9: 0x000000000000 in add (safegguf)")

    def test_falls_back_to_first_error_line_for_setup_failure(self):
        frame = coverage_lane.first_failing_frame(FILE_NOT_FOUND)
        self.assertIsNotNone(frame)
        self.assertIn("FileNotFound", frame)

    def test_empty_log_has_no_frame(self):
        self.assertIsNone(coverage_lane.first_failing_frame(b""))


class TaxonomySchemaTests(unittest.TestCase):
    def test_incident_taxonomies_are_distinct_and_complete(self):
        self.assertEqual(len(set(coverage_lane.INCIDENT_TAXONOMIES)),
                         len(coverage_lane.INCIDENT_TAXONOMIES))
        for taxonomy in coverage_lane.SETUP_TAXONOMIES:
            self.assertTrue(taxonomy.startswith("setup_"))
        expected = (set(coverage_lane.CRASH_TAXONOMIES)
                    | {coverage_lane.TAXONOMY_TIMEOUT, coverage_lane.TAXONOMY_OOM}
                    | set(coverage_lane.SETUP_TAXONOMIES))
        self.assertEqual(set(coverage_lane.INCIDENT_TAXONOMIES), expected)

    def test_layer_mapping(self):
        mapping = {
            coverage_lane.TAXONOMY_VALIDATOR_CRASH: "validator",
            coverage_lane.TAXONOMY_ENGINE_CRASH: "engine",
            coverage_lane.TAXONOMY_UNKNOWN_CRASH: "unknown",
            coverage_lane.TAXONOMY_TIMEOUT: "runtime",
            coverage_lane.TAXONOMY_OOM: "runtime",
            coverage_lane.TAXONOMY_SETUP_MISSING_CORPUS: "setup",
            coverage_lane.TAXONOMY_SETUP_FILE_NOT_FOUND: "setup",
            coverage_lane.TAXONOMY_SETUP_BUILD_FAILURE: "setup",
            coverage_lane.TAXONOMY_SETUP_ERROR: "setup",
        }
        for taxonomy, layer in mapping.items():
            self.assertEqual(coverage_lane.incident_layer(taxonomy), layer)
            self.assertIn(layer, coverage_lane.INCIDENT_LAYERS)

    def test_required_incident_fields_are_pinned(self):
        self.assertEqual(
            tuple(coverage_lane.REQUIRED_INCIDENT_FIELDS),
            ("layer", "taxonomy", "repro_status", "input_sha256", "commit",
             "toolchain", "command", "stderr_tail", "first_failing_frame"))


class SummaryTotalsTests(unittest.TestCase):
    def test_setup_failures_are_counted_separately_from_crashes(self):
        summary = {
            "targets": [
                {"status": "setup_missing_corpus",
                 "taxonomy": "setup_missing_corpus"},
                {"status": "setup_build_failure",
                 "taxonomy": "setup_build_failure"},
                {"status": "validator_crash", "taxonomy": "validator_crash",
                 "crash_artifact": "a.gguf"},
                {"status": "unknown_crash", "taxonomy": "unknown_crash",
                 "crash_artifact": "b.gguf"},
            ],
            "corpus": {"entries": 0, "bytes": 0},
        }
        totals = coverage_lane.summary_totals(summary)
        self.assertEqual(totals["setup_failures"], 2)
        self.assertEqual(totals["validator_crashes"], 1)
        self.assertEqual(totals["unknown_crashes"], 1)
        self.assertEqual(totals["engine_crashes"], 0)
        self.assertEqual(totals["crash_artifacts"], 2)


class IncidentJsonSchemaTests(unittest.TestCase):
    """Both artifact writers must emit the strict incident schema."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = self._tmp.name
        self.artifacts = os.path.join(root, "artifacts")
        self.cache = os.path.join(root, "cache")
        self.corpus = os.path.join(root, "corpus")
        for path in (self.artifacts, self.cache, self.corpus):
            os.makedirs(path)
        self.log_path = os.path.join(self.artifacts, "target.log")
        self.args = types.SimpleNamespace(
            zig="zig",
            artifacts_dir=self.artifacts,
            cache_root=self.cache,
            corpus_dir=self.corpus,
        )
        self.target = {
            "step": "fuzz-cov-gguf-spec-little",
            "profile": "gguf-spec",
            "endian": "little",
            "kind": "required",
        }
        self._patch("zig_version", lambda _zig: "0.14.1")
        self._patch("git_commit", lambda: "deadbeef")

    def _patch(self, name, value):
        original = getattr(coverage_lane, name)
        setattr(coverage_lane, name, value)
        self.addCleanup(setattr, coverage_lane, name, original)

    def _write_log(self, blob):
        with open(self.log_path, "wb") as f:
            f.write(blob)

    def _add_corpus_entry(self, payload, index=7):
        corpus_dir = os.path.join(self.cache, "f", "test-name")
        os.makedirs(corpus_dir, exist_ok=True)
        path = os.path.join(corpus_dir, str(index))
        with open(path, "wb") as f:
            f.write(payload)
        return path

    def _read_incident(self, artifact):
        json_path = os.path.join(self.artifacts, os.path.splitext(artifact)[0] + ".json")
        with open(json_path, encoding="utf-8") as f:
            return json.load(f)

    def _assert_strict_schema(self, meta):
        for field in coverage_lane.REQUIRED_INCIDENT_FIELDS:
            self.assertIn(field, meta)
        self.assertEqual(meta["commit"], "deadbeef")
        self.assertEqual(meta["toolchain"], "zig 0.14.1")
        self.assertTrue(meta["stderr_tail"])

    def test_no_input_incident_carries_strict_schema(self):
        self._write_log(UNKNOWN_SEGV)
        name = coverage_lane.save_crash_without_input(
            self.args, self.target, self.log_path,
            coverage_lane.TAXONOMY_UNKNOWN_CRASH, "unknown",
            command="zig build --fuzz fuzz-cov-gguf-spec-little")
        meta = self._read_incident(name)
        self._assert_strict_schema(meta)
        self.assertEqual(meta["layer"], "unknown")
        self.assertEqual(meta["taxonomy"], coverage_lane.TAXONOMY_UNKNOWN_CRASH)
        self.assertEqual(meta["repro_status"], "repro_not_attempted")
        self.assertIsNone(meta["input_sha256"])
        self.assertEqual(meta["command"], "zig build --fuzz fuzz-cov-gguf-spec-little")
        self.assertIn("Segmentation fault", meta["stderr_tail"])

    def test_input_incident_carries_strict_schema_and_input_sha(self):
        payload = b"GGUF\x03\x00\x00\x00\x01\x02\x03\x04"
        entry = self._add_corpus_entry(payload)
        self._write_log(OOM_BLOB)
        artifact, repro_status, repro_calls, taxonomy = coverage_lane.save_crash_artifact(
            self.args, self.target, [(7, entry)], self.cache, self.log_path,
            coverage_lane.TAXONOMY_OOM, "validator", attempt_repro=False,
            command="zig build --fuzz fuzz-cov-gguf-spec-little")
        self.assertEqual(repro_status, "repro_not_attempted")
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_OOM)
        meta = self._read_incident(artifact)
        self._assert_strict_schema(meta)
        self.assertEqual(meta["layer"], "runtime")
        self.assertEqual(meta["input_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertIn("OutOfMemory", meta["stderr_tail"])

    def test_unknown_crash_without_repro_stays_unknown(self):
        entry = self._add_corpus_entry(b"GGUF\x03\x00\x00\x00")
        self._write_log(UNKNOWN_SEGV)
        self._patch("repro_verdict", lambda *a, **k: ("repro_not_confirmed", b""))
        artifact, repro_status, _, taxonomy = coverage_lane.save_crash_artifact(
            self.args, self.target, [(7, entry)], self.cache, self.log_path,
            coverage_lane.TAXONOMY_UNKNOWN_CRASH, "unknown",
            command="zig build --fuzz fuzz-cov-gguf-spec-little")
        self.assertEqual(repro_status, "repro_not_confirmed")
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_UNKNOWN_CRASH)
        meta = self._read_incident(artifact)
        self.assertEqual(meta["taxonomy"], coverage_lane.TAXONOMY_UNKNOWN_CRASH)
        self.assertEqual(meta["layer"], "unknown")

    def test_unknown_crash_with_confirmed_repro_is_promoted(self):
        entry = self._add_corpus_entry(b"GGUF\x03\x00\x00\x00\x01\x02\x03\x04")
        self._write_log(UNKNOWN_SEGV)
        self._patch("repro_verdict", lambda *a, **k: ("repro_confirmed", b""))
        artifact, repro_status, repro_calls, taxonomy = coverage_lane.save_crash_artifact(
            self.args, self.target, [(7, entry)], self.cache, self.log_path,
            coverage_lane.TAXONOMY_UNKNOWN_CRASH, "unknown",
            command="zig build --fuzz fuzz-cov-gguf-spec-little")
        self.assertEqual(repro_status, "repro_confirmed")
        self.assertLessEqual(repro_calls, coverage_lane.MAX_REPRO_CALLS)
        self.assertEqual(taxonomy, coverage_lane.TAXONOMY_VALIDATOR_CRASH)
        meta = self._read_incident(artifact)
        self.assertEqual(meta["taxonomy"], coverage_lane.TAXONOMY_VALIDATOR_CRASH)
        self.assertEqual(meta["layer"], "validator")


class RunBoundedSetupClassificationTests(unittest.TestCase):
    """End-to-end: a failing target process is classified from its log."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.artifacts = os.path.join(self.root, "artifacts")
        self.cache_root = os.path.join(self.root, "cache-root")
        self.corpus = os.path.join(self.root, "persisted-corpus")
        for path in (self.artifacts, self.cache_root, self.corpus):
            os.makedirs(path)
        self._orig_repo_root = coverage_lane.REPO_ROOT
        coverage_lane.REPO_ROOT = self.root
        self.addCleanup(setattr, coverage_lane, "REPO_ROOT", self._orig_repo_root)
        self._patch("zig_version", lambda _zig: "0.14.1")
        self._patch("git_commit", lambda: "deadbeef")
        self.target = {
            "step": "fuzz-cov-gguf-spec-little",
            "profile": "gguf-spec",
            "endian": "little",
            "kind": "required",
        }
        self.args = types.SimpleNamespace(
            zig=None,
            cache_root=self.cache_root,
            corpus_dir=self.corpus,
            artifacts_dir=self.artifacts,
            startup_timeout=5,
            stall_seconds=5,
        )

    def _patch(self, name, value):
        original = getattr(coverage_lane, name)
        setattr(coverage_lane, name, value)
        self.addCleanup(setattr, coverage_lane, name, original)

    def _fake_zig(self, output, crash=False):
        script = os.path.join(self.root, "fake-zig.sh")
        message = os.path.join(self.root, "fake-zig.out")
        with open(message, "wb") as f:
            f.write(output)
        body = '#!/bin/sh\ncat "$(dirname "$0")/fake-zig.out"\n'
        body += "kill -ABRT $$\n" if crash else "exit 1\n"
        with open(script, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR)
        return script

    def _run(self, output, crash=False):
        self.args.zig = self._fake_zig(output, crash=crash)
        return coverage_lane.run_bounded(
            self.args, self.target, 1, self.artifacts,
            os.path.join(self.cache_root, "zig-global"))

    def test_missing_corpus_is_setup_never_validator(self):
        result = self._run(FILE_NOT_FOUND)
        self.assertEqual(result["taxonomy"], coverage_lane.TAXONOMY_SETUP_MISSING_CORPUS)
        self.assertEqual(result["status"], coverage_lane.TAXONOMY_SETUP_MISSING_CORPUS)
        self.assertTrue(result["status"].startswith("setup_"))
        self.assertIsNone(result["crash_artifact"])

    def test_file_not_found_with_corpus_present_is_setup(self):
        os.makedirs(os.path.join(self.root, "tests", "corpus"))
        result = self._run(FILE_NOT_FOUND)
        self.assertEqual(result["taxonomy"], coverage_lane.TAXONOMY_SETUP_FILE_NOT_FOUND)
        self.assertNotEqual(result["status"], coverage_lane.TAXONOMY_VALIDATOR_CRASH)
        self.assertIsNone(result["crash_artifact"])

    def test_build_failure_is_setup(self):
        os.makedirs(os.path.join(self.root, "tests", "corpus"))
        result = self._run(BUILD_FAILURE)
        self.assertEqual(result["taxonomy"], coverage_lane.TAXONOMY_SETUP_BUILD_FAILURE)
        self.assertNotEqual(result["status"], coverage_lane.TAXONOMY_VALIDATOR_CRASH)

    def test_production_crash_is_validator_and_writes_strict_schema(self):
        os.makedirs(os.path.join(self.root, "tests", "corpus"))
        result = self._run(VALIDATOR_PANIC, crash=True)
        self.assertEqual(result["status"], coverage_lane.TAXONOMY_VALIDATOR_CRASH)
        self.assertEqual(result["crash_site"], "validator")
        self.assertIsNotNone(result["crash_artifact"])
        meta_path = os.path.join(
            self.artifacts, os.path.splitext(result["crash_artifact"])[0] + ".json")
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        for field in coverage_lane.REQUIRED_INCIDENT_FIELDS:
            self.assertIn(field, meta)
        self.assertEqual(meta["layer"], "validator")
        self.assertEqual(meta["taxonomy"], coverage_lane.TAXONOMY_VALIDATOR_CRASH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
