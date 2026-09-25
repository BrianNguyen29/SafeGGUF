<div align="center">

# 🛡️ SafeGGUF

**Enterprise-Grade, Memory-Safe Pre-Admission Firewall & Arithmetic Validator for GGUF Models**

[![CI](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.13.0-orange.svg?style=flat-square&logo=zig)](https://ziglang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v0.3.7--dev-blue.svg?style=flat-square)](https://github.com/BrianNguyen29/SafeGGUF)
[![Upstream ggml](https://img.shields.io/badge/ggml-0.23.0%20(e91ded11)-blueviolet.svg?style=flat-square)](https://github.com/ggml-org/ggml/tree/e91ded11bdcd78c42f9c8d3978ff6686eb4c1226)
[![Docker](https://img.shields.io/badge/Docker-Distroless%20%3C%205MB-2496ED.svg?style=flat-square&logo=docker)](Dockerfile)
[![Audit](https://img.shields.io/badge/Security-Internal%20Verification%20Passed-blue.svg?style=flat-square)](production_audit_report.md)

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#python-bindings--anti-toctou">Python (Anti-TOCTOU)</a> •
  <a href="#c-abi-shared-library">C-ABI</a> •
  <a href="#cloud-native--kubernetes">Kubernetes & Docker</a> •
  <a href="#hybrid-triage--offline-engine">Hybrid Triage</a> •
  <a href="#security-audit--verification">Security Audit</a>
</p>

</div>

---

## ⚡ Overview

**SafeGGUF** is a high-performance, memory-safe, overflow-checked structural and arithmetic validator for **GGUF (v2 & v3)** model files, written in pure Zig with **zero external package dependencies**. 

In modern LLM infrastructure (such as `llama.cpp`, `vLLM`, or `Ollama`), model headers, metadata arrays, and tensor descriptor tables are completely **attacker-controlled**. Corrupted or weaponized model files can trigger silent 64-bit integer wraparounds, heap out-of-bounds corruption, and unconstrained memory exhaustion before inference even begins.

SafeGGUF acts as an **Ingress Pre-Admission Firewall**, inspecting model topology using a constant **64 KiB sliding-window reader** with strictly bounded heap allocations governed by `QuotaAllocator` (128 MB default ceiling). It deterministically rejects malicious or malformed payloads in $< 10\text{ ms}$ before any tensor weights are mapped into host memory.

```
                              SAFEGGUF INGRESS PIPELINE
                              
   [ External Model Ingestion: HuggingFace / S3 / Custom Storage / Upload ]
                                      |
                                      v
   +-----------------------------------------------------------------------+
   | TIER 1: SafeGGUF Deterministic Pre-Admission Firewall                 |
   | - 64-bit Checked Arithmetic (Prevents dimension & product overflows)  |
   | - Wrapping QuotaAllocator (128 MB cap) & WorkBudget (10M units)       |
   | - Zero-Padding Invariant Enforcement (Anti-steganography tamper check)|
   | - 64 KiB sliding buffer + QuotaAllocator bounds (latency < 10ms)      |
   +-----------------------------------------------------------------------+
                     /                                   \
        Exit Code 2 /                                     \ Exit Code 0
                   /                                       \
                  v                                         v
   +------------------------------+         +-------------------------------+
   | 🚫 HARD REJECT (DROP)        |         | TIER 2: Hybrid Triage Filter  |
   | - Blocked at cluster ingress |         | - safegguf-triage             |
   | - Zero inference memory used |         | - Rule Classifier / Jev AI    |
   | - Security alert dispatched  |         +-------------------------------+
   +------------------------------+                     /       \
                                       Score < 0.20   /         \ Score >= 0.20
                                                     /           \ (Risk >= Medium)
                                                    v             v
                                           +-------------+  +---------------+
                                           | ✅ PROD POD |  | ⚠️ CANARY ZONE|
                                           | (Admit)     |  | (Quarantine)  |
                                           +-------------+  +---------------+
```

---

## ✨ Key Features

* **🛡️ Zero-Compromise Arithmetic Safety:** Checked operations (`checkedAdd`, `checkedMul`, `checkedAlignUp`) everywhere. Eliminates 64-bit integer wrap vulnerabilities (e.g. *CVE-2024-2182*, *CVE-2024-34062*, *CVE-2025-53630*).
* **⚡ Bounded Memory Architecture:** Evaluates arbitrarily large multi-gigabyte models through a 64 KiB sliding I/O window with bounded metadata allocations under `QuotaAllocator`. Tensor weight payloads are never loaded into host RAM.
* **🔒 In-Process Anti-TOCTOU Defense:** Direct File Descriptor validation (`safegguf.validate_fd(fd)`) provides TOCTOU-resistance when downstream loaders consume the same open file descriptor or immutable Content-Addressable Storage (CAS) digest.
* **🌐 Enterprise C-ABI & Zero-Libc:** Exported shared and static libraries (`safegguf.dll`, `libsafegguf.so`, `libsafegguf.a`) easily integrated with C, C++, Rust, Go, or Python.
* **🔄 Endianness Auto-Detection:** Seamlessly inspects Little-Endian and Big-Endian GGUF v2/v3 models (`--endian auto`) without manual configuration.
* **🤖 Hybrid Semantic Triage (Air-Gapped & Offline):** Built-in deterministic Rule Classifier provides sub-millisecond threat categorization and risk scoring with **zero token cost and zero network requirements**, plus live TypeSafe Jev System One integration.
* **🐳 Ultra-Minimal Cloud-Native Footprint:** Distroless multi-stage Docker image ($< 5\text{ MB}$) with non-root security context (`runAsUser: 65532`) and drop-in Kubernetes InitContainer manifests.
* **🎯 Deterministic Exit Code Contract:** Fail-closed taxonomy (`0` PASS, `2` REJECT, `64` USAGE, `70` SOFTWARE, `74` IOERR) built specifically for automated CI/CD and production ingress gates.

---

## 📊 Defense Comparison

| Threat Vector / Protection | Naive Parsers | Native Inference Loaders | SafeGGUF (v0.3.7-dev) |
| :--- | :---: | :---: | :---: |
| **Integer Arithmetic Overflows** | ❌ Vulnerable | ⚠️ Intermittent Checks | ✅ **100% Checked Arithmetic** |
| **Peak Memory During Validation** | $O(N)$ (File Size) | $O(N)$ (`mmap` allocation) | ✅ **64 KiB I/O Window + Quota Cap** |
| **TOCTOU Attack Protection** | ❌ None (Path-only) | ❌ None | ✅ **Kernel FD / CAS Digest** |
| **Anti-Steganography Zero-Padding** | ❌ Ignored | ❌ Ignored | ✅ **Enforced (Strict Alignment)** |
| **Resource Exhaustion (Memory DoS)** | ❌ Unbounded | ⚠️ Partial Checks | ✅ **QuotaAllocator & WorkBudget** |
| **Air-Gapped Semantic Scoring** | ❌ None | ❌ None | ✅ **Rule Classifier (<10ms)** |
| **Container Footprint** | > 100 MB | > 1 GB (CUDA / Runtimes) | ✅ **Distroless Static < 5 MB** |

---

## 🚀 Quick Start

### 1. Build from Source

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF

# Build optimized ReleaseSafe binary
zig build -Doptimize=ReleaseSafe

# Binary output: zig-out/bin/safegguf
./zig-out/bin/safegguf --version
```

### 2. Inspect a Model

```bash
# Basic inspection with auto-detected endianness
safegguf inspect /path/to/model.gguf --endian auto

# Structured JSON output for automated CI/CD pipelines
safegguf inspect /path/to/model.gguf --profile llama-cpp --format json

# Enforce custom memory and work budget constraints
safegguf inspect /path/to/model.gguf --max-memory-mb 64 --max-work-budget 5000000
```

### 3. Exit Codes Contract

SafeGGUF implements a deterministic, fail-closed exit taxonomy:

| Exit Code | Constant | Meaning | Action in Ingress Pipeline |
| :---: | :--- | :--- | :--- |
| **`0`** | `EX_OK` | **PASS**: Model satisfies all structural & arithmetic invariants | **Admit to inference engine** |
| **`2`** | `EX_REJECT` | **REJECT**: Malformed header, arithmetic overflow, or tamper | **Hard Drop & quarantine** |
| **`64`** | `EX_USAGE` | **USAGE**: Invalid CLI parameters or flags | Reject invocation / fix script |
| **`70`** | `EX_SOFTWARE` | **SOFTWARE**: Internal invariant error or host OOM | Alert operations / retry |
| **`74`** | `EX_IOERR` | **IOERR**: File missing, unreadable, or storage failure | Check volume mount / disk |

---

## 🐍 Python Bindings & Anti-TOCTOU Defense

SafeGGUF provides in-process Python bindings (`safegguf-py`) designed to eliminate **Time-Of-Check to Time-Of-Use (TOCTOU)** race conditions in multi-tenant inference services.

### Installation

```bash
pip install ./bindings/python
```

### Usage

```python
import os
import safegguf

# 1. Path-based validation
result = safegguf.validate_path("/models/llama-3.gguf", profile="llama-cpp")
if result.is_valid:
    print("✅ Model validated safely!")
else:
    print(f"🚫 Model rejected! Error: {result.error_message} (Code: {result.exit_code})")

# 2. Kernel-level Anti-TOCTOU validation (Recommended for Production)
# Open the file once in read-only mode and validate directly against the File Descriptor.
with open("/models/llama-3.gguf", "rb") as f:
    # Validates in-kernel handle: file swapping on disk has zero effect
    res = safegguf.validate_fd(f.fileno(), profile="llama-cpp")
    if not res.is_valid:
        raise SecurityError(f"Pre-admission check failed: {res.error_message}")

    # File pointer (seek offset) is preserved strictly at its original position
    print("Model verified on raw descriptor — ready for safe inference!")
```

---

## 🔌 C-ABI Shared Library

SafeGGUF exports a pure, standard C-ABI requiring **zero external dependencies and zero libc linking**.

### Header: `include/safegguf.h`

```c
#include "safegguf.h"
#include <stdio.h>

int main(void) {
    safegguf_options_v1_t options = {
        .struct_size = sizeof(safegguf_options_v1_t),
        .profile = SAFEGGUF_PROFILE_LLAMA_CPP,
        .endian = SAFEGGUF_ENDIAN_AUTO,
        .max_alloc_bytes = 128 * 1024 * 1024, /* 128 MB ceiling */
        .max_work_units = 10000000,
        .max_scanned_bytes = 0,               /* 0 = default limit */
        .reserved = NULL
    };

    safegguf_result_t result;

    // Validate directly via path (or safegguf_validate_fd_v1 for open descriptors)
    int rc = safegguf_validate_path_v1("/path/to/model.gguf", &options, &result);
    if (rc == SAFEGGUF_OK) {
        printf("Model passed structural validation.\n");
    } else {
        printf("Rejected (exit %d, [%s] %s): %s\n",
               rc, result.category, result.error_code, result.message);
    }
    return rc;
}
```

---

## ☸️ Cloud-Native & Kubernetes

### 1. Ultra-Minimal Distroless Docker Image

The multi-stage [`Dockerfile`](Dockerfile) compiles a static `x86_64-linux-musl` binary on `gcr.io/distroless/static-debian12:nonroot`:
* **Image Size:** $< 5\text{ MB}$
* **User Context:** Non-root (`nonroot:nonroot`, UID `65532`)
* **Vulnerability Surface:** Zero shell, zero package manager, zero runtime bloat.

```bash
docker build -t safegguf:v0.3.6 .
docker run --rm -v $(pwd)/models:/models:ro safegguf:v0.3.6 inspect /models/model.gguf
```

### 2. Kubernetes Ingress InitContainer

Deploy SafeGGUF as an admission firewall inside your inference Pods before `llama.cpp` or `vLLM` starts:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: llm-inference-pod
  namespace: ai-serving
spec:
  volumes:
    - name: model-volume
      persistentVolumeClaim:
        claimName: models-pvc
  initContainers:
    - name: safegguf-firewall
      image: ghcr.io/briannguyen29/safegguf:v0.3.6
      command:
        - /usr/local/bin/safegguf
        - inspect
        - /models/model.gguf
        - --profile
        - llama-cpp
        - --endian
        - auto
      resources:
        limits:
          cpu: "500m"
          memory: "128Mi"
      volumeMounts:
        - name: model-volume
          mountPath: /models
          readOnly: true
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532
  containers:
    - name: llama-cpp-server
      image: ghcr.io/ggerganov/llama.cpp:server
      # Starts ONLY if the InitContainer above exited with code 0 (PASS)
```

---

## 🧠 Hybrid Semantic Triage (`safegguf-triage`)

The hybrid triage engine [`tools/safegguf-triage/safegguf_triage.py`](tools/safegguf-triage/safegguf_triage.py) classifies incoming model risks into quantitative typed judgments.

```bash
# Air-gapped offline triage (0 network, 0 token cost, latency < 10ms)
python tools/safegguf-triage/safegguf_triage.py /path/to/model.gguf --mode offline --format json
```

### Sample Output (Malicious Integer Overflow Exploit)

```json
{
  "file": "cve-2025-53630-cumulative-overflow.gguf",
  "profile": "llama-cpp",
  "safegguf_verdict": "REJECT",
  "safegguf_exit_code": 2,
  "error_code": "E_ArithmeticOverflow",
  "triage": {
    "engine": "offline_bayesian_rule_engine",
    "risk_score": 0.980,
    "severity": "Critical",
    "threat_category": "Arithmetic-Exploit",
    "downstream_exploit_prob": 0.95,
    "recommendation": ">>> HARD_DROP_INGRESS <<<",
    "rationale": "Rejected by SafeGGUF with error code 'E_ArithmeticOverflow' in category 'arithmetic'."
  }
}
```

---

## 🧪 Comprehensive Security Audit & Verification

SafeGGUF has been subjected to continuous multi-agent adversarial auditing and empirical stress testing across **16 test suites and over 76,000 operations**:

```
+----------------------------------------------------------------------------------------------------------------+
|                                    EMPIRICAL VERIFICATION & AUDIT MATRIX                                       |
+----+---------------------------------------+-----------------------------+-------------------+-----------------+
| ID | Test Suite / Security Domain          | Scenarios & Probing Targets | Test Count        | Pass Rate       |
+----+---------------------------------------+-----------------------------+-------------------+-----------------+
| 01 | Zig Unit & Fuzz Sweep                 | 35 GGML types, limits, mem  | 78 / 78 tests     | PASS (100.0%)   |
| 02 | CLI E2E Contract Suites               | Exit codes 0, 2, 64, 70, 74 | 10 / 10 suites    | PASS (100.0%)   |
| 03 | Negative Corpus Suite                 | 6 error classes & 3 CVEs    | 15 / 15 cases     | REJECT (Exit 2) |
| 04 | BigInt Arithmetic Oracle              | Python BigInt cross-oracle  | 74,626 ops        | PASS (100.0%)   |
| 05 | Advanced Security Testbed             | Wraparounds, padding, DoS   | 62 / 62 tests     | PASS (100.0%)   |
| 06 | Adversarial Endianness Sweep          | Big-Endian v2/v3 detection  | 577 / 577 tests   | PASS (100.0%)   |
| 07 | Truncation & Binary Noise Stress      | Byte slicing & 500 noise    | 949 / 949 slices  | PASS (100.0%)   |
| 08 | CLI Resource & Boundary Probing       | Probing N >= 2^44, 2^64-1   | 38 / 38 probes    | PASS (Exit 64)  |
| 09 | Python Bindings Integration           | Path & Raw FD validation    | 10 / 10 suites    | PASS (100.0%)   |
| 10 | C-ABI Adversarial Probes              | NULL, handle 0/-1, TOCTOU   | 57 / 57 probes    | PASS (100.0%)   |
| 11 | C-ABI Deep Stress & Concurrency       | 0..100k chars, 32 threads   | 48 / 48 probes    | PASS (100.0%)   |
| 12 | Hybrid Triage Unit & Integration      | Bayesian logic, JSON/Text   | 38 / 38 tests     | PASS (100.0%)   |
| 13 | Triage Challenger 1 Probing           | Security fixtures matrix    | 42 / 42 probes    | PASS (100.0%)   |
| 14 | Triage Challenger 2 Probing           | Zero leakage (39 exploits:0)| 56 / 56 probes    | PASS (100.0%)   |
| 15 | Triage Network Adversarial Stress     | Socket timeout, 502, HTML   | 45 / 45 tests     | PASS (100.0%)   |
| 16 | Cloud-Native Packaging Audit          | Distroless, K8s, docs audit | 18 / 18 checks    | PASS (100.0%)   |
+----+---------------------------------------+-----------------------------+-------------------+-----------------+
| OVERALL: OVER 76,000 ADVERSARIAL & EMPIRICAL PROBES PASSED WITH 100.0% SUCCESS RATE (0 REGRESSIONS)            |
+----------------------------------------------------------------------------------------------------------------+
```

For full forensic details, audit logs, and signatures, see [`production_audit_report.md`](production_audit_report.md).

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

<div align="center">
  <b>Built with precision in pure Zig. Protecting AI infrastructure from malicious weights.</b>
</div>
