# SafeGGUF — Production Readiness Review & Remediation Plan

> **Archived historical document.** This is a point-in-time snapshot kept for provenance;
> it is not the current security contract. Current guarantees live in
> [`SECURITY.md`](../../SECURITY.md); current operations docs are
> [`docs/runbooks/`](../runbooks/) and [`docs/production_deployment.md`](../production_deployment.md).

**Project:** SafeGGUF  
**Repository:** `BrianNguyen29/SafeGGUF`  
**Review snapshot:** `main` at commit `e9d88be0fcc2e06a78af1cc5985f1447b594f9a5`  
**Snapshot date:** 2026-10-01  
**Latest tagged release observed:** `v0.3.6`  
**Purpose:** Đưa SafeGGUF từ một validator có lõi kỹ thuật tốt lên mức có thể vận hành đáng tin cậy trong môi trường production, đặc biệt ở pipeline tiếp nhận GGUF không tin cậy, multi-tenant, Kubernetes/CI/CD, Python/C-ABI và supply chain.

---

## 1. Executive Summary

SafeGGUF hiện có một **core validator tốt và đáng giữ nguyên hướng kiến trúc**. Các phần đáng tin cậy nhất gồm:

- Reader dùng `pread` và sliding window thay vì mmap toàn bộ file.
- Checked arithmetic trên các trường attacker-controlled.
- Allocation quota, logical work budget và scanned-byte budget được tách biệt.
- Structural validation có kiểm overlap, alignment, tensor geometry, duplicate metadata/tensor names.
- Differential oracle với pinned upstream ggml.
- Real-world corpus và rolling-upstream canary.
- Release binary có checksum, Sigstore và SBOM/attestation.
- CLI contract tương đối chặt chẽ.

Tuy nhiên, **toàn bộ stack chưa đạt mức production-ready cho hostile ingestion** vì có các lỗ hổng và sai lệch ở integration/release/deployment layer.

Các blocker quan trọng nhất:

1. **Kubernetes “anti-TOCTOU” flow hiện không đảm bảo hash thuộc về đúng bytes đã validate.**
2. **C ABI path API chưa có parity với CLI trong việc reject non-regular files**, nên FIFO/device/socket có thể gây hành vi blocking hoặc contract khác nhau.
3. **Python binding cho phép integer wrapping vào `ctypes.c_uint64`**, có thể làm sai resource policy.
4. **Python native library discovery tìm trong CWD/workspace**, tạo executable/library hijacking surface.
5. **Container multi-arch workflow và Dockerfile không khớp kiến trúc thực tế.**
6. **CI trên `main` hiện đỏ**; lỗi cụ thể đã quan sát:
   - seed fuzz corpus không còn được generate nhưng script vẫn báo thành công;
   - coverage fuzz phân loại lỗi setup `FileNotFound` thành `validator_crash`;
   - macOS Python/C-ABI test từng panic với exit `134`;
   - nightly fuzz và coverage fuzz fail lặp lại sau commit hiện tại.
7. **Branch `main` hiện không được branch protection/ruleset bảo vệ** theo metadata quan sát.
8. **Assurance report có các claim mạnh hơn bằng chứng thực tế**, đặc biệt một số “100%” metric của Jev/triage là self-consistency hơn là independent validation.

Định hướng đúng không phải rewrite parser. Nên ưu tiên:

> **Stabilize assurance → harden boundaries → make deployment immutable → formalize release gates → add operational controls → reduce overclaims.**

---

# 2. Phạm vi đánh giá

Đánh giá bao phủ các vùng chính:

- `src/`
  - GGUF reader
  - parser
  - metadata validation
  - arithmetic
  - structural validation
  - validator orchestration
  - CLI
  - C ABI
- `bindings/python/`
- `tools/safegguf-triage/`
- `tests/`
  - unit/regression
  - negative corpus
  - differential
  - oracle
  - mutation fuzz
  - coverage-guided fuzz
  - adversarial harnesses
  - real corpus
- `.github/workflows/`
- `Dockerfile`
- `deploy/k8s/`
- `SECURITY.md`
- `README.md`
- production/audit/remediation documents.

Không coi `test_report.md`, `production_audit_report.md` hay các internal audit script là bằng chứng độc lập nếu chúng chỉ tự đánh giá trên cùng codebase.

---

# 3. Trạng thái hiện tại đã xác minh

## 3.1 Git / governance

Tại snapshot:

- `main = e9d88be0fcc2e06a78af1cc5985f1447b594f9a5`
- commit merge này không có Git signature verification.
- `main` trả về trạng thái:
  - `protected: false`
  - không có repository ruleset.
- Không quan sát thấy open issue hoặc open PR tại thời điểm review.

### Ý nghĩa production

CI tốt vẫn chưa đủ nếu branch có thể bị direct-push mà không cần required checks.

Đối với security-sensitive parser, branch governance là một phần của security control, không chỉ workflow hygiene.

---

## 3.2 CI / workflow health

### `CI` trên HEAD hiện tại

Push run của `CI` trên commit `e9d88be0` đã **failure**.

Các job đáng chú ý:

- Oracle & differential trên Ubuntu: **success**
- Oracle & differential trên macOS: **success**
- Bench Ubuntu: **success**
- Bench macOS: **success**
- Windows standalone push: **success**
- Core Ubuntu: **failure**
- Core macOS: **failure**
- Fuzz Ubuntu: **failure**
- Fuzz macOS: **failure**

### Root cause đã xác định: seed corpus regression

`tests/generate_fixtures.py` trước đây:

```python
corpus_dir = ...
os.makedirs(corpus_dir, exist_ok=True)
for fname in os.listdir(DIR):
    if fname.endswith(".gguf"):
        shutil.copyfile(...)
```

Sau thay đổi hiện tại, block này bị thay bằng security-testbed generation nhưng log vẫn in:

```text
All fixtures and seed corpus generated successfully.
```

Trong khi `tests/corpus` không được tạo.

Hậu quả:

- `tests/fuzz_target.zig` gọi:
  - `openDir("tests/corpus")`
- mutation fuzz cũng yêu cầu `tests/corpus`
- nightly fuzz fail
- coverage fuzz fail
- core Linux fail.

### Lỗi assurance taxonomy

Coverage fuzz gần nhất báo:

```text
validator_crash (no recoverable input)
```

nhưng log thực tế cho thấy failure từ setup/corpus chứ không phải validator crash.

Đây là lỗi nghiêm trọng về observability:

> Hệ thống assurance đang **misclassify infrastructure/setup failure thành validator security incident**.

Production-grade security testing phải phân biệt ít nhất:

- product crash
- harness crash
- environment/setup failure
- corpus missing
- timeout
- OOM
- fuzz engine crash
- workflow infrastructure failure.

---

## 3.3 Real corpus

Real-corpus run gần nhất trên cùng HEAD:

- **19/19 selected entries matched expected verdict**
- khoảng **1.12 GB** corpus được đánh giá
- coverage floors được đáp ứng.

Đây là tín hiệu tốt cho parser compatibility.

---

## 3.4 Rolling upstream canary

Rolling canary gần nhất:

- upstream ggml khoảng `0.25.3`
- không có divergence mới so với pinned baseline
- không có `SafeGGUF PASS / upstream REJECT` mới.

Có nhiều intentional false reject:

```text
SafeGGUF REJECT / upstream PASS
```

được phân loại là safe subset/compatibility divergence.

Đây là trạng thái hợp lý cho một admission validator bảo thủ.

---

# 4. Threat Model production đề xuất

SafeGGUF cần xác định rõ các actor và trust boundary thay vì chỉ nói “untrusted file”.

## 4.1 Attacker capabilities nên giả định

Một model uploader độc hại có thể:

- điều khiển toàn bộ bytes của `.gguf`;
- điều khiển metadata count, tensor count, lengths, dimensions, types, offsets;
- tạo file rất lớn;
- dùng sparse file;
- truncate file trong khi validator đang đọc;
- thay file path qua rename/symlink/PVC writer;
- tạo FIFO/socket/device nếu API cho phép path;
- tạo metadata gây worst-case hashing/sorting;
- submit nhiều request đồng thời;
- cố làm validator sử dụng quá nhiều CPU/RAM/I/O;
- lợi dụng differences giữa CLI, C ABI, Python binding;
- lợi dụng downstream parser differences;
- kiểm soát working directory trong một số deployment;
- đưa giá trị config/resource limits bất thường qua API layer;
- tạo malformed UTF-8, nested arrays, deep recursion;
- race với hash/sign/attestation step.

## 4.2 Không nên giả định

Không nên giả định:

- path là immutable chỉ vì volume mount read-only;
- FD đồng nghĩa content immutable;
- success của fuzz workflow đồng nghĩa no bugs;
- Zig memory safety loại bỏ mọi DoS;
- `PASS` có nghĩa model an toàn về hành vi;
- hash sau validation chứng minh hash thuộc bytes đã validate;
- external AI classifier là security oracle.

---

# 5. Security guarantees cần công bố chính xác

SafeGGUF nên cam kết các guarantee sau, và **chỉ** các guarantee này:

## 5.1 Có thể cam kết

- checked integer arithmetic trên các invariant được validate;
- bounded validator-managed allocation;
- bounded logical work theo accounting implementation;
- bounded scanned bytes trên code path được charge;
- structural consistency theo selected profile;
- deterministic exit taxonomy;
- pinned upstream compatibility baseline;
- false-reject-biased safe subset.

## 5.2 Không nên cam kết tuyệt đối

Không dùng các từ:

- “unbypassable”
- “completely safe”
- “TOCTOU immune”
- “guaranteed secure”
- “zero risk”
- “production enterprise ready” nếu release gate đang đỏ.

Thay bằng:

- “defense-in-depth”
- “path-replacement resistant when validating an already-open descriptor”
- “requires immutable handoff for full admission integrity”
- “bounded validator-managed resource use”
- “not an OS-level CPU/RSS/wall-clock sandbox”.

---

# 6. P0 — Blocker trước khi production

---

## P0-01 — Khôi phục CI / fuzz corpus

### Hiện trạng

`generate_fixtures.py` không còn tạo `tests/corpus`, nhưng vẫn báo “seed corpus generated”.

### Rủi ro

- PR/commit có thể merge trong khi fuzz assurance đã thực tế bị vô hiệu hóa.
- Nightly/coverage fuzz failure trở thành noise.
- Security incident taxonomy sai.
- Engineer có thể bỏ qua red workflow vì “biết là flake”.

### Sửa

Tách rõ:

```text
generate_fixtures.py
generate_seed_corpus.py
generate_security_testbed.py
```

Hoặc:

```python
generate_fixtures()
generate_seed_corpus()
generate_security_testbed()
```

Mỗi bước fail-fast.

Không dùng:

```python
except Exception:
    print("Warning")
```

cho required CI generation.

### Acceptance criteria

- `tests/corpus` tồn tại sau generator.
- corpus có minimum count đã định.
- corpus manifest có hash.
- `zig build test` chạy từ fresh checkout.
- mutation fuzz chạy từ fresh checkout.
- nightly fuzz chạy xanh ít nhất 7 ngày liên tục.
- coverage fuzz chạy xanh ít nhất 7 ngày liên tục.
- nếu corpus missing:
  - taxonomy = `harness_setup_failure`
  - không bao giờ = `validator_crash`.

---

## P0-02 — Sửa classification của coverage fuzz

### Problem

`FileNotFound`, build failure hoặc corpus setup failure bị gắn `validator_crash`.

### Taxonomy đề xuất

```text
validator_crash
validator_panic
validator_timeout
validator_oom

fuzz_engine_crash
harness_crash
harness_timeout

setup_missing_corpus
setup_build_failure
setup_dependency_failure

runner_infrastructure_failure
unknown_failure
```

### Rule

Chỉ gắn `validator_crash` khi:

- process đang chạy target validator;
- signal/exit code chứng minh crash;
- stack trace chạm production source;
- hoặc repro deterministic bằng standalone target.

### Acceptance criteria

Mỗi incident JSON phải có:

```json
{
  "layer": "validator|harness|engine|infra",
  "taxonomy": "...",
  "repro_status": "...",
  "input_sha256": "...",
  "commit": "...",
  "toolchain": "...",
  "command": "...",
  "stderr_tail": "...",
  "first_failing_frame": "..."
}
```

---

## P0-03 — Điều tra và sửa macOS C-ABI/Python panic

### Đã quan sát

macOS job từng chết:

```text
thread ... panic: reached unreachable code
Abort trap: 6
exit code 134
```

trong:

```text
python bindings/python/tests/test_binding.py
```

### Production requirement

FFI layer không được panic process trên invalid input hoặc ordinary API call.

### Hướng điều tra

Ưu tiên kiểm:

- handle conversion trên macOS;
- `ctypes` struct layout;
- `c_ssize_t` vs `intptr_t`;
- library architecture;
- Zig shared library ABI;
- `GeneralPurposeAllocator` deinit panic/leak behavior;
- using `File{ .handle = handle }` với borrowed descriptor;
- interaction với `file.getPos()` / `seekTo()`.

### Acceptance criteria

Trên:

- Ubuntu x86_64
- macOS arm64
- Windows x86_64

phải có:

```text
10,000 repeated calls
invalid fd tests
closed fd tests
directory fd tests
pipe fd tests
socket fd tests
concurrent calls
```

với:

```text
0 panic
0 process abort
0 UAF
0 double close
0 descriptor mutation
```

---

## P0-04 — C ABI reject non-regular files

### Hiện trạng

CLI đã có:

```text
stat.kind != .file => reject/io error
```

nhưng C ABI path API không enforce tương đương.

### Attack surface

Potential problematic paths:

- FIFO
- Unix socket
- character device
- block device
- directory
- procfs pseudo-file.

### Risk

`open()` có thể block trước khi resource budget chạy.

### Sửa

POSIX path validation nên dùng một strategy:

```text
open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW)
fstat(fd)
require S_ISREG
```

Nếu symlink được phép, policy cần explicit.

Không được dựa vào extension.

### Acceptance matrix

| Target | CLI | C ABI path | Python path |
|---|---|---|---|
| Regular file | validate | validate | validate |
| Directory | immediate error | immediate error | immediate error |
| FIFO no writer | immediate error | immediate error | immediate error |
| Socket | error | error | error |
| Char device | error | error | error |
| Block device | error | error | error |

---

## P0-05 — Python integer coercion hardening

### Hiện trạng

Resource limits được truyền vào:

```python
ctypes.c_uint64
```

mà không validate Python integer range.

### Risk examples

```text
-1      -> UINT64_MAX
2**64   -> 0
2**64+1 -> 1
```

Có thể phá security policy.

### Sửa

Tạo helper:

```python
def _parse_u64_limit(name, value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ...
    if value < 0 or value > UINT64_MAX:
        raise ...
    return value
```

Quy định rõ:

```text
0 = use configured default
```

### Test bắt buộc

- `-1`
- `-2`
- `2**64`
- `2**65`
- `True`
- `False`
- `1.0`
- `"128"`
- numpy integer nếu hỗ trợ
- Python bigint cực lớn.

---

## P0-06 — Sửa K8s immutable handoff

### Hiện trạng nguy hiểm

Flow hiện tại:

```text
validate /models/model.gguf
sha256sum /models/model.gguf
runtime verify hash
runtime load /models/model.gguf
```

Nếu source path mutable:

```text
A validated
A replaced by B
B hashed
B verified
B loaded
```

B chưa từng được validate.

### Thiết kế production đúng

```text
untrusted source
   |
   v
copy once into private staging
   |
   v
freeze / make immutable
   |
   +--> validate staged bytes
   |
   +--> hash staged bytes
   |
   v
publish by digest to immutable CAS
   |
   v
runtime loads exact digest
```

### Implementation options

Ưu tiên:

1. Object store immutable version IDs.
2. CAS keyed by SHA-256.
3. fs-verity.
4. read-only snapshot.
5. sealed memfd.
6. private `emptyDir` staging with no writer after copy.

### Kubernetes flow đề xuất

```text
download/copy init container
        |
        v
/private-stage/model.gguf
        |
        v
SafeGGUF validator
        |
        v
sha256
        |
        v
rename into /validated/<digest>
        |
        v
serving container read-only
```

Serving container không mount original PVC model path.

---

## P0-07 — Sửa container multi-arch

### Hiện trạng

Workflow publish:

```text
linux/amd64
linux/arm64
```

nhưng Dockerfile build:

```text
zig-linux-x86_64
-Dtarget=x86_64-linux-musl
```

### Sửa

Mapping:

```text
TARGETARCH=amd64 -> x86_64-linux-musl
TARGETARCH=arm64 -> aarch64-linux-musl
```

Builder nên chạy trên `$BUILDPLATFORM`.

### Release tests

Bắt buộc:

```text
docker run --platform linux/amd64 ...
docker run --platform linux/arm64 ...
```

Validate:

- `uname`/binary architecture;
- `safegguf --version`;
- parse valid fixture;
- reject malformed fixture.

---

## P0-08 — Branch protection và release governance

### Hiện trạng

`main` chưa protected.

### Production configuration đề xuất

Require:

- pull request before merge;
- 1–2 approving reviewers;
- stale review dismissal;
- code owner review cho:
  - `src/`
  - `include/`
  - `bindings/`
  - `.github/workflows/`
  - `deploy/`
  - `Dockerfile`
  - `SECURITY.md`;
- signed commits hoặc verified merge strategy nếu phù hợp;
- required status checks;
- no force push;
- no branch deletion;
- admin bypass chỉ dùng break-glass.

### CODEOWNERS

Thêm `.github/CODEOWNERS`.

---

# 7. P1 — Hardening trước public production adoption

---

## P1-01 — Python native library discovery

### Problem

Binding tìm library ở:

```text
repo_root/zig-out
cwd/zig-out
system lookup
SAFEGGUF_LIB_PATH
```

Nếu working directory attacker-controlled, có thể load malicious shared library.

### Production design

Chỉ nên có ba mode:

1. Packaged native library.
2. Explicit trusted absolute path.
3. System install path được admin quản lý.

Không tìm tự động trong CWD.

### Extra validation

Nếu explicit path:

- absolute;
- regular file;
- owner/mode check optional;
- hash pin optional;
- reject world-writable directory in hardened mode.

---

## P1-02 — Python packaging production-grade

### Hiện trạng

`setup.py` chưa bundle native library.

### Đề xuất

Chuyển sang:

```text
pyproject.toml
PEP 517
wheel builds
```

Publish wheels:

- manylinux x86_64
- manylinux aarch64
- macOS arm64
- macOS x86_64 nếu cần
- Windows x86_64.

Wheel chứa đúng native library.

### CI

Test install thực:

```text
python -m venv clean
pip install dist/*.whl
cd /tmp
python -c "import safegguf; ..."
```

Điều này bắt được dependency vào repo/CWD.

---

## P1-03 — C ABI versioning strategy

Hiện có `v1`, đây là hướng đúng.

Cần formalize:

```text
ABI major
struct_size
reserved fields
symbol stability
error-code stability
thread-safety guarantees
ownership guarantees
```

### Khuyến nghị

Export:

```text
safegguf_api_version()
safegguf_build_info_v1()
```

Document:

- input pointer ownership;
- result buffer ownership;
- fd ownership;
- whether FD offset changes;
- thread safety;
- async-signal safety: no;
- fork behavior.

---

## P1-04 — FD semantics chính xác

Không gọi unconditional:

```text
anti-TOCTOU
immune to TOCTOU
```

Đúng hơn:

> validating an already-open descriptor prevents pathname replacement from changing the file object being validated.

Nhưng không ngăn:

- in-place write
- truncate
- filesystem corruption
- mutable inode content.

### Production options

Để stronger guarantee:

- immutable CAS;
- sealed memfd;
- fs-verity;
- exclusive snapshot;
- open FD + inode mutation restrictions.

---

## P1-05 — Detect file mutation during validation

Có thể thêm optional hardened mode.

Trước parse:

```text
fstat:
dev
ino
size
mtime/ctime
```

Sau parse:

```text
fstat again
```

Reject nếu:

- size changed;
- inode identity changed;
- mtime/ctime changed.

Không tạo cryptographic immutability, nhưng bắt nhiều race.

Có thể expose:

```text
--require-stable-file
```

---

## P1-06 — File size admission limit

Current resource controls không đồng nghĩa bounded file size.

Thêm:

```text
max_file_size
```

CLI/API option:

```text
--max-file-size-bytes
```

Production default nên do deployer set theo service tier.

Ví dụ:

- 8 GiB
- 32 GiB
- 128 GiB

tùy platform.

Reject trước parsing.

---

## P1-07 — Wall-clock timeout

Logical work budget không chặn:

- slow filesystem;
- FUSE stall;
- network filesystem stall;
- kernel/page-cache delays.

Deployment phải có:

```text
wall_clock_timeout
CPU quota
process kill
```

Nếu SafeGGUF chạy như service, dùng per-request deadline.

---

## P1-08 — Process isolation

Production hostile uploads nên validate trong process/container tách biệt.

Recommended:

```text
validator worker
non-root
read-only root filesystem
no network
seccomp
drop all capabilities
memory max
pids max
cpu.max
timeout
```

Không chạy validator trong cùng process inference server nếu có thể tránh.

---

# 8. Resource control review

## 8.1 Allocation quota

Hiện quota chỉ kiểm memory qua wrapped allocator.

Không bao gồm:

- stack
- Zig runtime overhead
- libc/system runtime nếu có
- page cache
- kernel memory
- Python interpreter memory
- filesystem buffers.

### Đề xuất

Document hai lớp:

```text
Layer 1: validator logical quota
Layer 2: process/container hard limit
```

Production cần cả hai.

---

## 8.2 WorkBudget

Work budget là thiết kế tốt.

Cần formalize cost model.

Ví dụ:

```text
metadata key parse = 1
metadata value parse = 1
array element = 1
tensor descriptor = 1
hash insert = log_factor
sort = N log N
```

### Đề xuất

Version cost model:

```text
work_model_version = 1
```

Tại sao?

Vì nếu version mới thay cost, cùng `max_work_units` sẽ có behavior khác.

---

## 8.3 Scanned-byte budget

Hiện không phải mọi reader byte đều được tính.

Cần nói rõ:

- scanned bytes là semantic scan;
- không phải physical disk bytes;
- sliding-window prefetch có thể đọc nhiều hơn.

Nếu muốn strict I/O budget, thêm:

```text
backend_read_bytes
backend_read_ops
```

ở reader.

Production benefit:

- ngăn crafted access pattern gây read amplification;
- đo thực tế.

---

# 9. Parser / structural core — đề xuất nâng cấp

Core hiện khá tốt, nhưng có thể harden thêm.

## 9.1 Hash-map collision resistance

`StringHashMap` có thể có worst-case behavior nếu hash không keyed/randomized đủ mạnh.

Cần kiểm Zig implementation/version cụ thể.

Nếu concern:

- use keyed hash;
- hoặc sort keys rồi detect duplicate;
- hoặc deterministic bounded comparison.

Với attacker-controlled metadata/tensor names, hash DoS là threat thực tế.

---

## 9.2 Duplicate metadata memory

Parser giữ copies của metadata keys để detect duplicate.

Ở 1M entries, quota là defense chính.

Có thể tối ưu:

- fingerprint + collision fallback;
- intern/hash-only structure;
- compact arena.

Không ưu tiên P0 vì quota đã bảo vệ.

---

## 9.3 Alignment limit

Ngoài:

```text
alignment > 0
alignment % 8 == 0
power-of-two under llama.cpp
```

nên có upper bound explicit:

```text
max_alignment
```

Ví dụ:

```text
1 MiB
```

hoặc theo upstream contract.

Tránh giant padding arithmetic/pathological sparse layout.

---

## 9.4 Metadata recursion

Current depth 16 tốt.

Nên test:

- exact 16
- 17 reject
- alternating nested arrays
- zero-length nested arrays.

---

## 9.5 Tensor dimension semantics

Ngoài overflow cần verify:

- zero dimension policy;
- `n_dims = 0`;
- signed-equivalent huge u64;
- row/block divisibility;
- quantized block constraints.

Đã có nhiều test, nhưng nên giữ matrix per ggml type.

---

# 10. Differential testing strategy

Hiện đây là điểm mạnh.

Nên formalize thành ba oracle:

## Oracle A — Pinned production baseline

Pinned ggml commit.

Blocking.

## Oracle B — Rolling upstream

Latest upstream branch.

Advisory.

## Oracle C — Real downstream runtime

Một minimal loader của llama.cpp release target.

Mục tiêu:

- validation outcome
- actual load success/failure
- no crash.

### Tại sao cần Oracle C

ggml parser compatibility không hoàn toàn đồng nghĩa llama.cpp loader behavior.

---

# 11. Fuzzing production-grade

## 11.1 Required lanes

### Lane A — deterministic corpus

Blocking PR.

### Lane B — mutation fuzz

Blocking PR với budget nhỏ.

### Lane C — coverage-guided

Nightly/advisory hoặc release gate.

### Lane D — FFI fuzz

C ABI + Python boundary.

### Lane E — filesystem fuzz

Path/FD targets:

- FIFO
- socket
- sparse file
- truncate during read
- rename
- hardlink
- symlink
- permission changes.

---

## 11.2 Corpus ownership

Không để corpus là side-effect mơ hồ.

Thêm:

```text
tests/corpus/manifest.json
```

Fields:

```json
{
  "version": 1,
  "generated_by": "...",
  "generator_version": "...",
  "entries": [
    {
      "name": "...",
      "sha256": "...",
      "class": "...",
      "expected": "PASS|REJECT"
    }
  ]
}
```

CI fail nếu:

- missing;
- count thấp hơn floor;
- hash mismatch.

---

## 11.3 Reproducibility

Mọi crash artifact có:

- seed;
- input;
- command;
- exact Zig version;
- commit;
- profile;
- endian;
- exit/signal;
- stack;
- minimized reproducer.

---

# 12. Negative corpus / CVE provenance

Đây là vùng repo làm khá tốt.

Cần formalize labels:

```text
byte-exact-cve-repro
mechanism-equivalent
synthetic-class-exemplar
regression-only
```

Không gọi synthetic fixture là CVE repro nếu không byte-equivalent.

Production security docs phải giữ chuẩn này.

---

# 13. Triage engine / AI integration

## 13.1 Hard rule

AI/LLM không được override SafeGGUF hard reject.

Correct architecture:

```text
SafeGGUF structural verdict
        |
        +--> reject => terminal
        |
        +--> pass => optional semantic policy
```

Không:

```text
LLM says safe -> override REJECT
```

---

## 13.2 Circular metrics

Nếu triage engine nhận:

```text
validation_status
error_code
category
```

rồi metric đo khả năng dự đoán chính `validation_status`, đó là self-consistency.

Không gọi là independent:

- precision
- recall
- F1
- exploit detection accuracy.

### Đề xuất

Hai benchmark:

1. **Policy consistency**
   - expected deterministic mapping.
2. **Independent semantic classifier**
   - features không chứa SafeGGUF verdict;
   - external labeled set.

---

## 13.3 Risk score

Hard-coded:

```text
0.98
0.75
0.52
```

không nên gọi probability nếu không calibrated.

Dùng:

```text
severity = LOW|MEDIUM|HIGH|CRITICAL
confidence_class = heuristic
```

Nếu muốn probability:
- calibration dataset;
- reliability curve;
- Brier score;
- confidence intervals.

---

## 13.4 External API privacy

Không gửi mặc định:

- absolute path;
- user directory;
- model storage path;
- internal hostnames;
- tenant identifiers.

Add redaction.

---

# 14. Docker hardening

## 14.1 Add `.dockerignore`

Loại:

```text
.git
.github
.zig-cache
zig-out
.cache
tests/fuzz-artifacts
*.md audit reports nếu không cần
.env
secrets
venv
__pycache__
```

---

## 14.2 Pin base image digest

Runtime image nên pin digest.

Builder image cũng nên pin.

---

## 14.3 No shell runtime

Distroless/nonroot là tốt.

Verify:

- no package manager
- no shell
- nonroot
- read-only rootfs
- minimal CA certificates nếu no network.

---

## 14.4 Container labels

Generate từ build metadata:

```text
org.opencontainers.image.version
revision
source
created
licenses
```

Không hardcode version riêng.

---

# 15. Kubernetes production design

## 15.1 Serving container securityContext

Không chỉ init container.

Serving container nên:

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

---

## 15.2 Resource limits

Validator:

```yaml
resources:
  requests:
    cpu: ...
    memory: ...
  limits:
    cpu: ...
    memory: ...
```

Thêm `activeDeadlineSeconds` hoặc controller timeout.

---

## 15.3 No network

Validator nên chạy với network denied nếu không cần download.

NetworkPolicy:

```text
deny all egress
deny all ingress
```

Downloader/stager tách container riêng.

---

## 15.4 Immutable model volume

Serving container chỉ mount:

```text
validated object store
```

không mount upload source.

---

## 15.5 Attestation

Attestation record nên gồm:

```json
{
  "schema_version": 1,
  "sha256": "...",
  "size": 123,
  "safegguf_version": "...",
  "safegguf_commit": "...",
  "profile": "llama-cpp",
  "limits": {...},
  "timestamp": "...",
  "verdict": "PASS"
}
```

Có thể ký attestation nếu crossing trust boundary.

---

# 16. CI/CD production gates

## 16.1 PR required checks

Recommended blocking:

```text
format
unit-linux
unit-macos
windows-native
cli-integration
c-abi
python-binding
negative-corpus
oracle-arithmetic
oracle-types
differential-pinned
mutation-fuzz-smoke
ffi-fuzz-smoke
bench-budget-regression
version-consistency
container-build-amd64
container-build-arm64
```

---

## 16.2 Nightly checks

Advisory nhưng phải alert:

```text
coverage fuzz
long mutation fuzz
real corpus
rolling upstream
filesystem race suite
ASAN/UBSAN downstream oracle nếu dùng C/C++
```

---

## 16.3 Release gates

Release tag không publish nếu bất kỳ điều nào sau fail:

- required CI red;
- nightly fuzz red trong N ngày do unresolved product/harness failure;
- branch HEAD không bằng release commit;
- dirty version metadata;
- SBOM generation fail;
- signature fail;
- architecture smoke fail;
- binary provenance fail;
- image provenance fail.

---

# 17. Supply chain hardening

## 17.1 GitHub Actions

Main CI pin SHA là tốt.

Container workflow phải làm tương tự.

Không dùng mutable:

```text
actions/...@v4
docker/...@v5
```

Pin full commit SHA.

---

## 17.2 Dependency policy

Zig toolchain:

- checksum pin;
- download source documented;
- reproducible version.

Oracle dependency:

- commit pin;
- source archive/hash pin nếu có thể.

---

## 17.3 SBOM

Current SBOM cho binary release là tốt.

Nên có:

- SPDX/CycloneDX for container;
- OCI attestation;
- source dependencies;
- toolchain provenance.

---

## 17.4 SLSA direction

Mục tiêu:

- provenance generated by CI;
- isolated builder;
- immutable source ref;
- signed attestations;
- no manual artifact replacement.

---

# 18. Versioning

Hiện version xuất hiện nhiều nơi:

```text
build.zig
Python __version__
setup.py
Docker labels
K8s image example
docs
```

### Production design

Một source:

```text
VERSION
```

hoặc build metadata generated từ Git tag.

Generate:

- Zig build option
- Python package version
- Docker label
- release name
- SBOM version.

### Release rule

Tag:

```text
vX.Y.Z
```

must equal embedded:

```text
X.Y.Z
```

Dev branch:

```text
X.Y.(Z+1)-dev+<sha>
```

---

# 19. Error taxonomy

Cần làm error codes ổn định và machine-readable.

Hiện có sự lẫn:

```text
ArithmeticOverflow
E_ArithmeticOverflow
```

ở docs/test/report.

### Đề xuất

Canonical public codes:

```text
SGGUF_E_INVALID_MAGIC
SGGUF_E_UNSUPPORTED_VERSION
SGGUF_E_ARITHMETIC_OVERFLOW
SGGUF_E_RESOURCE_LIMIT
SGGUF_E_INVALID_UTF8
...
```

Internal Zig error name có thể khác.

Không expose implementation-specific enum string như ABI contract.

---

# 20. Structured result schema

Nên có JSON schema version.

Ví dụ:

```json
{
  "schema_version": 1,
  "status": "PASS|REJECT|ERROR",
  "exit_code": 0,
  "error_code": null,
  "category": null,
  "stage": null,
  "profile": "llama-cpp",
  "endian": "little",
  "file_size": 123,
  "limits": {},
  "build": {
    "version": "...",
    "commit": "..."
  }
}
```

### Production requirement

Backward-compatible minor additions.

Breaking change => schema major increment.

---

# 21. Observability

Production validator cần metrics.

## Core metrics

```text
safegguf_requests_total
safegguf_pass_total
safegguf_reject_total
safegguf_error_total

safegguf_validation_seconds
safegguf_file_bytes
safegguf_peak_alloc_bytes
safegguf_work_units
safegguf_scanned_bytes

safegguf_reject_by_error_code
```

Không dùng unbounded labels như:

```text
filename
tensor_name
metadata_key
```

---

# 22. Logging

Structured JSON.

Fields:

```text
request_id
tenant_id hash/pseudonym
digest
file_size
profile
duration_ms
verdict
error_code
stage
version
commit
```

Không log:

- full model path nếu chứa tenant data;
- full metadata values;
- secrets;
- user prompt.

---

# 23. Operational runbooks

Cần ít nhất:

## Runbook A — validator crash

- quarantine input;
- store digest;
- preserve artifact;
- collect version/commit;
- disable affected release;
- reproduce.

## Runbook B — false reject

- capture corpus entry;
- compare pinned oracle;
- compare rolling oracle;
- classify intentional vs regression.

## Runbook C — false accept/downstream crash

Severity critical.

- isolate model;
- stop admission;
- reproduce downstream;
- promote fixture;
- release patch.

## Runbook D — fuzz nightly red

Phân biệt:
- harness
- infrastructure
- validator.

Không để red kéo dài nhiều ngày mà không issue.

---

# 24. Release support policy

Define:

```text
supported minor
security patch window
EOL
```

Ví dụ:

```text
latest 0.3.x supported
previous minor security-only for 90 days
```

Hoặc semantic version ổn định hơn khi `1.0`.

---

# 25. Production API architecture đề xuất

SafeGGUF nên có 3 lớp rõ ràng:

```text
libSafeGGUF
    |
    +-- CLI
    |
    +-- C ABI
    |
    +-- Python binding
```

Mọi layer phải dùng chung:

- option validation
- profile defaults
- error mapping
- file target policy
- resource limits.

Không duplicate logic.

Tạo internal helper:

```text
validatePathPolicy()
validateFdPolicy()
validateOptions()
mapError()
```

---

# 26. Profile semantics

Hiện CLI và API default có thể khác.

Production recommendation:

### Option A — explicit profile

Không có default cho security admission.

Require:

```text
--profile llama-cpp
```

### Option B — default same everywhere

Nếu cần ergonomic default:

```text
llama-cpp
```

cho mọi entry point.

Không để:

```text
CLI default A
Python default B
C default C
```

---

# 27. Config precedence

Formalize:

```text
per-call option
> service config
> env
> built-in default
```

Hoặc nếu muốn env override:

document exact order.

Không để hidden env thay đổi security policy bất ngờ trong shared library.

### Khuyến nghị

C ABI `v1`:
- options fully explicit;
- không đọc env nếu options != NULL.

CLI:
- env allowed.

Library:
- deterministic.

---

# 28. Environment variable hardening

Hiện invalid env values thường bị silent-ignore.

Production better:

- invalid security env => startup error;
- hoặc warning + metrics.

Không silently fallback nếu operator nghĩ đã set quota.

Ví dụ:

```text
SAFEGGUF_MAX_MEMORY_MB=abc
```

nên fail startup/hardened mode.

---

# 29. Config object

Nên có:

```zig
pub const ValidationPolicy = struct {
    profile
    endian
    max_file_size
    max_alloc_bytes
    max_work_units
    max_scanned_bytes
    max_metadata_entries
    max_tensors
    max_string_bytes
    max_depth
    require_regular_file
    require_stable_file
}
```

Một object duy nhất giảm config drift.

---

# 30. Testing resource boundaries

Mỗi limit phải test:

```text
limit - 1
limit
limit + 1
0
max uint
```

bao gồm:

- tensors
- metadata count
- string bytes
- tensor name
- dimensions
- array elements
- variable arrays
- recursion
- alloc bytes
- work units
- scan bytes
- file size
- alignment.

---

# 31. Concurrency testing

Production service có concurrent requests.

Test:

```text
1
2
8
32
128
```

parallel validations.

Verify:

- no data race;
- no global mutable state;
- no fd offset corruption;
- no result cross-contamination;
- stable memory.

Python `_fd_lock` hiện serialize toàn bộ FD validation.

Nếu không cần thiết, có thể bỏ để tăng throughput sau khi C ABI proves thread-safe.

---

# 32. Performance SLO

Cần benchmark target.

Ví dụ:

```text
P50 < X ms metadata-only
P95 < Y ms
memory peak < configured quota
syscalls < threshold
```

Theo file size classes:

- 1 MB
- 100 MB
- 1 GB
- 10 GB
- large sparse.

Mục tiêu không nhất thiết fixed globally, nhưng regression threshold phải có.

---

# 33. Benchmark methodology

Không chỉ benchmark happy path.

Benchmark:

- metadata-heavy
- many tensors
- long keys
- string arrays
- bool arrays
- overlap-heavy
- max alignment
- malformed late-failure.

Late-failure files quan trọng vì attacker muốn ép validator làm nhiều work trước reject.

---

# 34. Filesystem behavior

Production tests nên cover:

- ext4
- XFS
- tmpfs
- overlayfs
- Kubernetes PVC
- object-store FUSE nếu dùng.

`pread` semantics và metadata stability có thể khác.

---

# 35. Sparse file handling

Attacker có thể tạo file có logical size rất lớn nhưng disk use nhỏ.

Nếu file size không capped, parser có thể chấp nhận offsets dựa trên huge logical size.

Thêm max_file_size và test sparse.

---

# 36. Symlink policy

Define rõ.

Options:

### Strict

Reject symlink path.

### Controlled

Resolve once:

```text
openat2 RESOLVE_NO_MAGICLINKS / RESOLVE_BENEATH
```

Linux hardened deployment.

Cross-platform fallback phải documented.

---

# 37. Windows security

Cần verify:

- reparse points;
- NTFS alternate streams;
- file handle sharing flags;
- mutation while open;
- device paths;
- named pipes.

Windows path surface khác POSIX đáng kể.

---

# 38. macOS security

Cần regression cho panic đã quan sát.

Ngoài ra:

- arm64 shared library;
- hardened runtime nếu distribute signed binary;
- codesign/notarization nếu muốn public binary adoption.

---

# 39. Release artifact verification

Current release verification tốt.

Thêm:

- provenance cho container image;
- per-platform binary smoke;
- artifact size sanity;
- deterministic version output.

---

# 40. Container image release

Tag strategy:

```text
v0.3.7
v0.3
sha-<commit>
```

Digest pin in deployment:

```text
image: ghcr.io/...@sha256:...
```

Không deploy `latest`.

Không deploy mutable `server` tags cho downstream inference trong security example.

---

# 41. Example deployment phải an toàn theo mặc định

Security project bị đánh giá theo example docs.

Nếu README có insecure K8s example, người dùng sẽ copy.

Do đó example phải:

- immutable model staging;
- image digest pin;
- nonroot;
- seccomp;
- drop caps;
- resource limits;
- network policy note;
- no mutable PVC handoff.

---

# 42. Documentation restructuring

Đề xuất:

```text
docs/
  architecture.md
  threat-model.md
  validation-guarantees.md
  production-deployment.md
  c-api.md
  python.md
  release-security.md
  testing-assurance.md
  runbooks/
```

Historical audit plans chuyển:

```text
docs/archive/
```

để không lẫn với current guarantees.

---

# 43. Security claims policy

Mọi claim phải gắn evidence class.

Ví dụ:

```text
Claim: Checked overflow rejection
Evidence:
- unit tests
- bigint oracle
- pinned differential
- fuzz corpus
```

Không viết:

```text
100% secure
```

---

# 44. Production checklist

Release candidate chỉ production-ready khi tất cả true:

## Source / governance

- [ ] main protected
- [ ] CODEOWNERS configured
- [ ] no direct push
- [ ] release commit reviewed
- [ ] required checks green

## Core

- [ ] unit tests green
- [ ] arithmetic oracle green
- [ ] type oracle green
- [ ] differential pinned green
- [ ] real corpus green
- [ ] rolling canary reviewed

## Fuzz

- [ ] deterministic corpus green
- [ ] mutation fuzz green
- [ ] FFI fuzz green
- [ ] coverage fuzz healthy
- [ ] no unresolved validator crash

## FFI

- [ ] C ABI path policy parity
- [ ] C ABI no panic
- [ ] Python integer validation
- [ ] packaged native lib
- [ ] no CWD library search

## Deployment

- [ ] immutable handoff
- [ ] container multiarch correct
- [ ] images digest pinned
- [ ] no network validator
- [ ] cgroup/resource limits
- [ ] wall-clock timeout

## Supply chain

- [ ] actions SHA pinned
- [ ] checksum manifest
- [ ] Sigstore
- [ ] SBOM
- [ ] provenance attestation

## Documentation

- [ ] no overclaim
- [ ] threat model current
- [ ] TOCTOU wording correct
- [ ] production example secure

---

# 45. Proposed backlog

| ID | Priority | Work item | Blocking production |
|---|---|---|---|
| PRD-001 | P0 | Restore fuzz seed corpus generation | Yes |
| PRD-002 | P0 | Fix fuzz incident taxonomy | Yes |
| PRD-003 | P0 | Reproduce/fix macOS FFI panic | Yes |
| PRD-004 | P0 | Reject non-regular targets in all APIs | Yes |
| PRD-005 | P0 | Python u64 option validation | Yes |
| PRD-006 | P0 | Immutable K8s staging/handoff | Yes |
| PRD-007 | P0 | Correct multiarch Docker builds | Yes |
| PRD-008 | P0 | Branch protection + required checks | Yes |
| PRD-009 | P1 | Remove CWD native library discovery | Yes for Python deployment |
| PRD-010 | P1 | Build self-contained Python wheels | Recommended |
| PRD-011 | P1 | Add max file size | Strongly recommended |
| PRD-012 | P1 | Add stable-file mutation detection | Recommended |
| PRD-013 | P1 | Pin container workflow actions | Yes for secure releases |
| PRD-014 | P1 | Pin deployment image digests | Yes |
| PRD-015 | P1 | Single version source | Recommended |
| PRD-016 | P1 | Canonical public error codes | Recommended |
| PRD-017 | P1 | JSON schema versioning | Recommended |
| PRD-018 | P1 | Service metrics/logging | Production ops |
| PRD-019 | P1 | Incident runbooks | Production ops |
| PRD-020 | P1 | Independent triage benchmark | If triage retained |
| PRD-021 | P2 | Result ownership API redesign | Library quality |
| PRD-022 | P2 | Hash collision hardening | Defense-in-depth |
| PRD-023 | P2 | Alignment upper bound | Defense-in-depth |
| PRD-024 | P2 | Filesystem matrix | Reliability |
| PRD-025 | P2 | macOS codesign/notarization | Distribution |

---

# 46. Definition of Done cho P0

SafeGGUF có thể chuyển từ “development hardened” sang “production candidate” khi:

1. HEAD required CI xanh.
2. Nightly/coverage fuzz không còn fail vì harness.
3. macOS C/Python panic được root-cause và regression-test.
4. C ABI/Python path behavior bằng CLI với non-regular files.
5. Python resource limits không wrap.
6. K8s example dùng immutable staged artifact.
7. Multiarch image được runtime-tested.
8. `main` protected.
9. Container release actions pin SHA.
10. Không còn public claim mâu thuẫn với `SECURITY.md`.

---

# 47. Definition of Production Ready

Đề xuất chỉ gắn nhãn production-ready khi đáp ứng đồng thời:

## Security

- không có open P0;
- không có unresolved crash trên supported platform;
- immutable admission handoff;
- OS-level sandbox/limits documented;
- threat model versioned.

## Reliability

- CI green liên tục;
- nightly fuzz healthy;
- real corpus green;
- release reproducible enough để verify.

## Operability

- metrics;
- logs;
- runbooks;
- upgrade/rollback procedure;
- supported version policy.

## Supply chain

- protected branch;
- pinned actions;
- signed release;
- SBOM;
- provenance;
- digest-pinned container deployment.

## API

- stable exit/error contract;
- ABI versioning;
- Python wheel packaging;
- no hidden CWD native dependency.

---

# 48. Proposed 3-phase roadmap

## Phase 1 — Stabilize and close blockers

Mục tiêu:

```text
HEAD green
security tests trustworthy
no crash in FFI
deployment semantics correct
```

Deliverables:

- PRD-001 → PRD-008.

Exit criteria:

- all P0 closed;
- 7 consecutive nightly runs healthy;
- one release candidate built but not yet promoted.

---

## Phase 2 — Production hardening

Deliver:

- Python packaging
- file-size limits
- stable-file detection
- image/action pinning
- config normalization
- structured schema
- metrics
- runbooks.

Exit criteria:

- staging deployment under synthetic hostile load;
- performance and resource thresholds met;
- rollback tested.

---

## Phase 3 — External assurance

Deliver:

- third-party security review;
- fuzz corpus sharing/OSS-Fuzz if feasible;
- SLSA/provenance maturity;
- public security guarantee document;
- `1.0` API stabilization.

---

# 49. Recommended architecture target

```text
             Untrusted Upload
                   |
                   v
          [Downloader / Stager]
                   |
                   v
        Private Immutable Staging
                   |
                   v
        [SafeGGUF Worker Sandbox]
          - no network
          - non-root
          - memory limit
          - CPU limit
          - timeout
          - regular file only
                   |
          PASS ----+---- REJECT
           |                 |
           v                 v
       SHA-256 CAS       Quarantine
           |
           v
     Signed Attestation
           |
           v
   Inference Runtime by Digest
```

Validator không nên chịu trách nhiệm:

- download;
- malware scanning;
- model behavior moderation;
- inference;
- external AI classification.

Separation of concerns làm hệ thống dễ audit hơn.

---

# 50. Recommended release gate architecture

```text
PR
 |
 +-- Unit
 +-- CLI
 +-- C ABI
 +-- Python
 +-- Pinned Oracle
 +-- Mutation Smoke
 +-- Bench
 +-- Windows Native
 |
 v
Protected main
 |
 +-- Nightly Coverage Fuzz
 +-- Long Mutation
 +-- Real Corpus
 +-- Rolling Upstream
 |
 v
Release Candidate
 |
 +-- All platform binaries
 +-- Multiarch images
 +-- Smoke tests
 +-- SBOM
 +-- Checksums
 +-- Sigstore
 +-- Provenance
 |
 v
Published Release
```

---

# 51. Specific code-level improvements

## 51.1 `tests/generate_fixtures.py`

Không swallow generator failure.

Bad:

```python
try:
    generate()
except Exception as e:
    print("Warning")
```

Good:

```python
generate()
assert corpus_count >= MIN_CORPUS
```

---

## 51.2 `src/c_api.zig`

Tạo helper:

```zig
fn openRegularFile(path: []const u8) !std.fs.File
```

Dùng cho mọi path API.

Sau stat:

```zig
if (stat.kind != .file) ...
```

FD API:

```zig
const stat = file.stat()
if (stat.kind != .file) ...
```

---

## 51.3 Python `core.py`

Thêm:

```python
_validate_limit()
_validate_fd()
_validate_explicit_library_path()
```

Không CWD fallback ở production package.

---

## 51.4 `limits.zig`

Invalid env không nên silent.

Có thể trả:

```zig
pub fn initFromEnv() !Limits
```

CLI map invalid env -> usage/config error.

---

## 51.5 `reader.zig`

Optional production counters:

```text
backend_read_ops
backend_read_bytes
```

Không chỉ test-only.

Cho metrics/perf audit.

---

# 52. Testing CI itself

Security tests cũng cần test.

Add meta-tests:

- generator thật sự tạo corpus;
- corpus count >= floor;
- fuzz harness taxonomy đúng với synthetic infra failures;
- artifact upload contains expected metadata;
- release workflow refuses red checks.

---

# 53. Chaos tests

Production staging nên chạy:

- kill validator mid-file;
- disk full;
- read-only temp;
- FUSE latency;
- file truncated mid-read;
- storage disappears;
- OOM kill;
- timeout kill.

Verify failure remains fail-closed.

---

# 54. Admission service mode

Nếu project muốn tiến xa hơn CLI/library, có thể xây một small daemon.

Nhưng không nên làm trước khi P0/P1 hoàn tất.

Service mode nên:

- local Unix socket hoặc gRPC;
- request references staged object by FD/digest;
- no raw arbitrary path by default;
- worker isolation;
- bounded queue;
- concurrency limit;
- metrics endpoint.

---

# 55. Rate limiting / abuse control

Validator correctness không chống volumetric DoS.

Ingress cần:

- upload rate limit;
- max concurrent validations per tenant;
- max total bytes/day;
- queue backpressure;
- circuit breaker.

---

# 56. Cache valid verdict by digest

Nếu immutable CAS:

```text
digest + safegguf_version + profile + policy_hash
```

có thể cache verdict.

Key không chỉ là digest.

Vì thay:

- validator version;
- profile;
- limits;
- compatibility baseline

có thể đổi verdict.

---

# 57. Policy hash

Tạo:

```text
policy_hash = SHA256(canonical policy config)
```

Attestation gồm:

```text
model_digest
validator_version
policy_hash
verdict
```

Giúp audit production rất mạnh.

---

# 58. Backward compatibility

Trước `1.0`, project có thể thay API.

Sau `1.0`:

- C ABI symbols stable;
- error codes stable;
- JSON schema stable;
- profile semantics versioned.

Có thể gọi profile:

```text
llama-cpp-v1
```

nếu upstream compatibility thay lớn.

---

# 59. Security review cadence

Đề xuất:

- mỗi release minor: internal threat review;
- mỗi quarter: fuzz/corpus review;
- mỗi major: third-party review;
- khi ggml type table thay: oracle audit;
- khi deployment architecture thay: TOCTOU re-review.

---

# 60. Kết luận

SafeGGUF có nền tảng parser/validator đủ tốt để tiếp tục đầu tư.

Điểm yếu chính hiện tại không nằm ở checked arithmetic hay basic parsing, mà ở **security composition**:

```text
file identity
FFI boundary
Python packaging
CI reliability
container architecture
Kubernetes handoff
branch governance
assurance semantics
```

Điều quan trọng nhất là không đánh đồng:

```text
core parser good
```

với:

```text
entire system production-ready
```

Sau khi đóng P0 và phần lớn P1, project có thể đạt một vị trí mạnh:

> **A hardened, reproducible, bounded, fail-closed GGUF pre-admission validator suitable for untrusted model-ingress pipelines when deployed with immutable artifact handoff and OS-level resource isolation.**

Đó là claim vừa mạnh vừa có thể chứng minh.

---

# Appendix A — Evidence Snapshot

Snapshot này dựa trên:

```text
main commit:
e9d88be0fcc2e06a78af1cc5985f1447b594f9a5
```

Các tín hiệu quan sát:

```text
CI HEAD: failure
Windows HEAD: success
Real Corpus HEAD: success
Rolling Upstream HEAD: success
Nightly Fuzz HEAD: failure
Coverage Fuzz HEAD: failure
```

Real corpus gần nhất:

```text
19/19 selected entries matched
~1.12 GB
```

Rolling canary:

```text
0 new divergence vs pinned baseline
```

Known HEAD CI defects:

```text
tests/corpus missing
fuzz generator success message incorrect
coverage taxonomy misclassifies setup failure
macOS Python/C-ABI panic observed
```

---

# Appendix B — Recommended issue titles

```text
[P0] Restore deterministic fuzz seed corpus generation
[P0] Separate harness/setup failures from validator crashes
[P0] Reproduce and fix macOS C-ABI/Python panic
[P0] Enforce regular-file target policy in C ABI and Python
[P0] Reject negative/overflow Python resource limits
[P0] Replace mutable K8s validate→hash flow with immutable staged CAS
[P0] Fix Docker multi-arch target compilation
[P0] Enable protected main + required checks + CODEOWNERS

[P1] Remove CWD native-library lookup from Python binding
[P1] Build self-contained platform wheels
[P1] Add max file size admission control
[P1] Add stable-file mutation detection
[P1] Pin all container-release GitHub Actions to commit SHA
[P1] Pin runtime container images by digest in deployment examples
[P1] Centralize version metadata
[P1] Introduce stable public error code namespace
[P1] Add JSON output schema version
[P1] Add production metrics and structured logging
[P1] Add incident response runbooks

[P2] Harden duplicate-key/tensor hash DoS behavior
[P2] Add explicit alignment upper bound
[P2] Add filesystem behavior matrix
[P2] Add macOS signing/notarization
```

---

# Appendix C — Minimal Production Gate

Nếu muốn một tiêu chuẩn ngắn gọn:

```text
NO-GO if:
- required CI red
- fuzz infrastructure broken
- unresolved native panic
- mutable model handoff
- branch unprotected
- Python can load native code from CWD
- architecture image mismatch
- non-regular file API parity missing
```

Production promotion chỉ khi tất cả NO-GO conditions đã được loại bỏ.

