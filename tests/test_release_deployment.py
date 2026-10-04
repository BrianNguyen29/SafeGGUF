"""Offline release rendering checks; no Kubernetes cluster access."""
import importlib.util
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_renderer", ROOT / "scripts/render_k8s_manifest.py")
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class ReleaseDeploymentTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Bash container smoke contract")
    def test_container_version_check_consumes_output_and_preserves_failure(self):
        workflow = (ROOT / ".github/workflows/container-release.yml").read_text()
        step = workflow.split("      - name: Run CLI contract on the built image\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1]).split('echo "$reported"', 1)[0]
        script = script.replace("${{ matrix.arch }}", "arm64").replace("${{ matrix.platform }}", "linux/arm64")
        script += 'printf "%s\\n" "$reported"\n'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / "output-complete"
            docker = directory / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import os, pathlib, sys, time\n"
                "print('SafeGGUF 0.1.0', flush=True)\n"
                "time.sleep(0.05)\n"
                "print('source_commit: test-commit', flush=True)\n"
                "pathlib.Path(os.environ['TEST_OUTPUT_MARKER']).write_text('complete')\n"
                "sys.exit(int(os.environ.get('TEST_LATE_EXIT', '0')))\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ["PATH"],
                       TEST_OUTPUT_MARKER=str(marker))
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "SafeGGUF 0.1.0")
            self.assertEqual(marker.read_text(), "complete")
            env["TEST_LATE_EXIT"] = "74"
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 74, result.stderr)
            self.assertEqual(result.stdout, "")

    @unittest.skipUnless(os.name == "posix" and shutil.which("sha256sum"), "POSIX checksum handoff")
    def test_serving_gate_checks_bytes_and_restores_runtime_directory(self):
        source = renderer.TEMPLATE.read_text(encoding="utf-8")
        server = source.split("    - name: llama-cpp-server\n", 1)[1]
        script = textwrap.dedent(server.split("        - |\n", 1)[1].split("      ports:\n", 1)[0])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("validated", "attestation", "app"):
                (root / name).mkdir()
                script = script.replace("/" + name, str(root / name))
            runtime = root / "app/llama-server"
            runtime.write_text("#!/bin/sh\npwd > \"$TEST_LAUNCH_MARKER\"\n", encoding="utf-8")
            runtime.chmod(0o755)
            marker = root / "launched"
            blob = b"validated model bytes"
            digest = hashlib.sha256(blob).hexdigest()
            model = root / "validated" / digest
            model.write_bytes(blob)
            pin = root / "attestation" / (digest + ".sha256")
            pin.write_text(f"{digest}  {digest}\n", encoding="utf-8")
            env = dict(os.environ, TEST_LAUNCH_MARKER=str(marker))

            def run():
                return subprocess.run(["/bin/sh", "-c", script], env=env,
                                      capture_output=True, timeout=10)

            self.assertEqual(run().returncode, 0)
            self.assertEqual(marker.read_text().strip(), str(root / "app"))
            marker.unlink()
            model.write_bytes(b"tampered")
            self.assertNotEqual(run().returncode, 0)
            self.assertFalse(marker.exists())
            model.write_bytes(blob)
            extra = root / "attestation" / ("b" * 64 + ".sha256")
            extra.write_text("extra pin", encoding="utf-8")
            self.assertNotEqual(run().returncode, 0)
            self.assertFalse(marker.exists())
            extra.unlink()
            pin.unlink()
            self.assertNotEqual(run().returncode, 0)
            self.assertFalse(marker.exists())

    def test_pinned_release_and_version_must_match(self):
        image = "ghcr.io/briannguyen29/safegguf:0.1.0@sha256:" + "a" * 64
        document = renderer.render(image, "0.1.0")
        self.assertIn(image, document)
        self.assertNotIn("SAFEGGUF_RELEASE_", document)
        prerelease = image.replace("0.1.0", "0.1.0-rc.1")
        self.assertIn(prerelease, renderer.render(prerelease, "0.1.0-rc.1"))
        for bad in (image.split("@")[0], image.replace("0.1.0", "latest"),
                    image.replace("a" * 64, "z" * 64), image.replace("brian", "Brian")):
            with self.assertRaises(ValueError):
                renderer.render(bad, "0.1.0")
        with self.assertRaises(ValueError):
            renderer.render(image, "0.1.1")

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "deployment.yaml"
            output.write_text("existing user artifact", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/render_k8s_manifest.py"),
                 "--validator-image", "ghcr.io/briannguyen29/safegguf:0.1.0@sha256:" + "a" * 64,
                 "--version", "0.1.0", "--output", str(output)],
                capture_output=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing user artifact")


if __name__ == "__main__":
    unittest.main()
