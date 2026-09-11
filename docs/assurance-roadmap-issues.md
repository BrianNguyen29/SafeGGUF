# Assurance Roadmap — Issues Breakdown (review nội bộ)

Nguồn: đề xuất 15 mục assurance (không mở rộng tính năng). Mỗi slice là vertical khép kín, demo/verify độc lập. Chưa publish lên GitHub.

Quy ước Type: **AFK** = đủ rõ để làm ngay trong quyền hiện tại; **HITL** = cần quyết định/phê duyệt của người.

---

## v0.3.6 — Assurance hardening

### 1. Nightly coverage-guided fuzzing thật sự — HITL · Blocked by: None
**What to build:** thêm job nightly libFuzzer (hoặc AFL++, cần chốt) chạy cả `gguf-spec` / `llama-cpp` × little/big-endian (khi profile cho phép); persist corpus giữa runs; auto-minimize crash; upload crashing input + minimized input + seed + profile + commit SHA + sanitizer info. Mục tiêu là coverage feedback, không phải thêm iterations.
**Acceptance criteria:**
- [ ] >= 30 phút/platform hoặc budget tương đương
- [ ] 0 crash / 0 panic / 0 leak / 0 unexpected exit
- [ ] corpus được persist giữa các lần chạy
**HITL:** chốt libFuzzer vs AFL++, nightly vs per-PR, nơi lưu corpus/artifacts, budget CI.

### 2. Arithmetic property tests (Python bigint oracle) — AFK · Blocked by: None
**What to build:** invariant tests cho `checkedAlignUp` / `checkedProduct` / `computeTensorBytes` / contiguous-offset: `alignUp(x,a) >= x`, `% a == 0`, idempotent khi đã aligned; `nbytes` đối chiếu Python arbitrary-precision trên hàng chục nghìn tuples (dims, type, alignment, offset), assert không wrapping (Python int không overflow ở `u64` nên làm oracle tốt).
**Acceptance criteria:**
- [x] oracle Python độc lập dùng integer arbitrary precision
- [x] generate hàng chục nghìn tuples và so với Zig implementation
- [x] overflow cases reject đúng

**Verify (done):** `tests/arithmetic_oracle.py` — phase 1 sweep ~77k tuples (alignUp / product / tensorBytes / contiguous chain, Python bigint, không cần C oracle); phase 2 cross-check qua CLI (exact-fit / one-byte-short → `TensorOutOfBounds`, chain alignUp, overflow → `ArithmeticOverflow`; cần ReleaseSafe binary). 61/61 Zig tests; bảng type khớp oracle upstream 43/43 (`test_oracle_types.py`).

### 3. UTF-8 boundary deterministic tests — AFK · Blocked by: None
**What to build:** test trực tiếp `validateUtf8Stream()` carry-buffer qua chunk 4096 bytes: split 4095|4096, 4094|4095..4096, 4093|4094..4096 cho sequence 2/3/4-byte (vd code point 4-byte tại byte 4093–4096); truncated final sequence, overlong encoding, invalid continuation byte. Không để mutation fuzz là lớp duy nhất bảo vệ logic này.
**Acceptance criteria:**
- [x] mọi split-point có case (2/3/4-byte, valid)
- [x] overlong / truncated / invalid continuation đều reject

**Verify (done):** utf8 carry-boundary tests trong `tests/validator_test.zig` (split 2/3/4-byte qua chunk 4096; truncated / overlong / invalid continuation reject); 61/61 Zig tests.

### 4. QuotaAllocator hardening tests — AFK · Blocked by: None
**What to build:** unit riêng cho resize tăng (40→80, accounting = peak = 80), resize vượt quota (80→120 với quota 100 → fail, allocated giữ 80), resize giảm (80→20, peak giữ 80), parent-resize-failure giữ accounting, stress alloc/resize/free ngẫu nhiên đối chiếu oracle độc lập (`allocated == sum(live)`, `allocated <= max`, `peak >= allocated`).
**Acceptance criteria:**
- [x] đủ 5 nhóm: tăng / vượt quota / giảm / parent-failure / stress
- [x] invariant accounting luôn đúng

**Verify (done):** 5 nhóm `quota_allocator:*` tests trong `tests/validator_test.zig` (grow / beyond-quota / shrink / parent-failure / deterministic stress); 61/61 Zig tests.

### 5. Oracle reproducibility stamp — AFK · Blocked by: None
**What to build:** `build_oracle.sh` ghi `.source-sha` (e91ded11…, ggml 0.23.0) vào `.cache/ggml-upstream/build/`; mismatch → `rm -rf build && cmake …`; luôn `cmake --build --target ggml` thay vì chỉ build khi thiếu `.so`.
**Acceptance criteria:**
- [x] stamp mismatch trigger rebuild
- [x] `--force` vẫn hoạt động, skip khi binary đã đúng commit

**Verify (done):** `.source-sha` stamp trong `tests/build_oracle.sh` (mismatch → rebuild; `--force` rebuild; đúng commit → skip); oracle 43/43 type traits khớp upstream (`test_oracle_types.py`).

### 6. Validator lifetime/threading contract + sửa wording SECURITY.md — AFK · Blocked by: None
**What to build:** ghi rõ trong docs/code: reuse tuần tự OK, cấm concurrent, `Document` phải deinit bằng cùng `Validator` trước khi hủy `Validator`; đồng thời hạ wording tuyệt đối ("Zero unchecked panics" → "attacker-controlled arithmetic dùng checked ops + covered bởi regression/differential/fuzz").
**Acceptance criteria:**
- [x] contract 3 dòng có trong docstring + docs
- [x] không còn guarantee tuyệt đối chưa chứng minh được

**Verify (done):** lifetime contract (sequential reuse / no concurrent / `deinitDocument` trên cùng Validator) trong docstring `src/validate/validator.zig`; SECURITY.md chuyển sang wording checked-arithmetic ("not guaranteed by construction alone"); 61/61 Zig tests.

---

## v0.4.0 — Fuzz & compatibility

### 7. Systematic differential generator — AFK · Blocked by: None (nên xong trước #8, #9)
**What to build:** generator sinh matrix thay vì fixture thủ công: mỗi 35 active types × (min row, multi-block, block±1, truncated exact/padded) — vd Q4_0: 31 reject / 32 pass / 33 reject / 64 pass; `n_dims` 0..5 + boundary `0/1/block/INT64_MAX-1/MAX/MAX+1/UINT64_MAX`; alignment `0/1/7/8/16/24/32/64…2^31/max-pow2/non-pow2-mult-8`; metadata scalar/empty/1-elem/max/truncated/bad-enum/nested.
**Acceptance criteria:**
- [x] generator thay thế viết tay, output deterministic
- [x] differential vs oracle (load/no-load) pass toàn matrix

**Verify (done):** `tests/differential_matrix.py` — generator deterministic ghi `tests/fixtures/matrix/*.gguf` (mỗi 35 active types × boundary shapes + n_dims/alignment/metadata boundaries); `tests/differential.py` sweep 269/269 fixtures (26 hand-written + matrix) khớp oracle 3 cột (SafeGGUF llama-cpp / upstream --load-data / --no-load). Chạy generator trước sweep; không có matrix thì harness chỉ còn 26 fixtures hand-written.

### 8. Real-world corpus manifest — HITL · Blocked by: #7 (khuyến nghị)
**What to build:** `tests/real-corpus-manifest.json` {url, sha256, expected_profile, expected_result}, nightly tải subset (Llama/Mistral/Qwen/Gemma/Phi/DeepSeek/embedding/reranker/multimodal, Whisper nếu tương thích); không commit file multi-GB; mục tiêu phát hiện false-reject.
**Acceptance criteria:**
- [ ] manifest + loader có verify sha256
- [ ] nightly subset xanh, false-reject được phát hiện
**HITL:** chốt URL list, license, dung lượng/network cho CI.

### 9. Negative CVE/upstream regression corpus — AFK · Blocked by: None
**What to build:** quy trình biến PoC upstream (parse/int-overflow/dims/types/alloc/metadata) thành fixture `cve-XXXX-YYYY.gguf` / `upstream-issue-N.gguf` kèm comment source + affected commit + expected behavior.
**Acceptance criteria:**
- [x] naming + comment convention được ghi lại
- [x] ít nhất khung + 1 fixture mẫu chạy trong CI

**Verify (done):** `tests/negative_corpus.py` — CASES registry ghi naming convention (`cve-YYYY-NNNN[-slug].gguf` / `upstream-issue-NNNN[-slug].gguf`) + per-case `source` / `affected_commit` / `expected_behavior`; 12 PoC-inspired fixtures trên 6 bug classes (parse/int-overflow/dims/types/alloc/metadata) + `tests/fixtures/negative/manifest.json`; verify pass 12/12 reject (exit 2) với đúng expected error_code. Standalone (deterministic generation, không phụ thuộc fixtures khác), verify pass cần ReleaseSafe binary.

---

## v0.5.0 — Production API

### 10. Validator ownership abstraction (`result.deinit()`) — HITL · Blocked by: #6
**What to build:** thay `validator.deinitDocument(&doc)` bằng `result.deinit()` tự mang allocator ownership/reference, giảm nguy cơ free sai allocator / quên deinit / hủy Validator sớm / dùng concurrent.
**Acceptance criteria:**
- [ ] API mới, mọi caller + test migrate
- [ ] cũ deprecated hoặc xóa theo chốt
**HITL:** chốt breaking-change vs alias, migration path.

### 11. Structured diagnostics + error categories — AFK · Blocked by: #6 (nên chốt sau contract)
**What to build:** mỗi rejection trả `{status, error_code, category(format|compatibility|arithmetic|resource|io|internal), stage, tensor_index/tensor/offset/expected_offset/key, message}`; parser giữ `ParseContext` (current_offset, metadata/tensor index, key, tensor_name) propagate lên; vd `E_NonContiguousTensorOffset` kèm tensor_index/tensor/offset/expected. Policy engine phân biệt được quarantine (format) / manual review (resource) / retry (io) / alert (internal).
**Acceptance criteria:**
- [x] rejection mẫu đầy đủ field, CLI JSON + text đều dùng
- [x] không còn message chung chung duy nhất

**Verify (done):** `Finding` đầy đủ `code`/`error_code`, `category` (format|compatibility|arithmetic|resource|io|internal; `categoryOf` exhaustive trong `src/gguf/error.zig`), `stage` + context `tensor_index`/`tensor`/`expected_offset`/`key`; CLI JSON và text đều render (`src/main.zig`); 62/62 Zig tests + 7/7 cli_test.py.

### 12. Profile `compatibility_target` trong JSON (phương án B, không breaking CLI) — AFK · Blocked by: None
**What to build:** giữ CLI `--profile llama-cpp` (tránh breaking), JSON trả thêm `{profile, compatibility_target: {project: ggml, version: 0.23.0, commit: e91ded…}}`; docs nói rõ đây là pre-admission subset derived từ ggml 0.23.0, không phải mọi llama.cpp.
**Acceptance criteria:**
- [x] JSON có đủ 3 field project/version/commit
- [x] docs làm rõ semantics

**Verify (done):** mọi JSON output (PASS/REJECT/ERROR) kèm provenance `{project: "ggml", version, commit}` từ `GGML_PINNED_VERSION/COMMIT` — field name theo profile: `compatibility_target` (llama-cpp) / `type_layout_source` (gguf-spec) (`src/main.zig`); semantics "safe pre-admission subset, không claim tương thích mọi llama.cpp" trong README; 7/7 cli_test.py assert provenance trên PASS/REJECT với cả hai tên field.

### 13. Supply-chain assurance — HITL · Blocked by: #12 (để embed profile-target)
**What to build:** artifact attestations + SLSA provenance + release signing + SBOM + `safegguf --version` in (version, commit, zig 0.13.0, target, profile-target ggml 0.23.0 e91ded11).
**Acceptance criteria:**
- [ ] provenance/SBOM/signing trên release
- [ ] `--version` đủ 5 dòng
**HITL:** chốt signing identity, SLSA level, SBOM format.

### 14. Benchmark + security budget regression — AFK · Blocked by: None
**What to build:** bench 10 / 1k / 10k / 100k / 1M tensor descriptors adversarial, 100k metadata keys, 256MB scanned strings; theo dõi wall-time, peak RSS, pread count, work units, scanned bytes; kiểm chứng 64 KiB sliding cache giảm syscall; threshold từ baseline CI runner (vd 10k descriptors < 100ms, pread không tăng tuyến tính từng field).
**Acceptance criteria:**
- [x] bench suite chạy được ở CI
- [x] baseline + threshold regression được ghi lại

**Verify (done):** `zig build bench` (ReleaseSafe) 3/3 tests green: descriptors 10/1k/10k/100k/1M (row 1M nâng `max_work_units`=50M + `max_total_alloc_bytes`=512MiB vì ~25M work units / ~148MiB peak vượt default), keys 1k/100k, strings 256MiB scanned; mỗi scale chạy cả direct lẫn buffered reader. Structural gates được enforce (fail CI): document PASS + header counts, logical_reads khớp hai reader kind, buffered read_syscalls <= file_size/64KiB + 16, buffered < direct khi direct >= 1000 preads (`/proc/self/io`; WSL local thiếu file nên gate syscall skip -- CI ubuntu chạy đủ, macOS n/a by design). Baseline ghi trong header `tests/bench_scales.zig` (runner-relative, không hard gate -- wall-time không ổn định giữa runner; local: 10k=36ms/9ms, 100k=297ms/62ms, 1M=3685ms/933ms direct/buffered, compile 26s + run 9s). CI: step `zig build bench --summary all` thêm sau core checks job `test` (cả ubuntu lẫn macos). Hai sửa đổi bắt buộc khi verify: bench output chuyển stderr (test-runner protocol chiếm stdout; output stdout làm build runner treo) và block UTF-8 64KiB fill at runtime thay comptime const (comptime const làm ReleaseSafe compile ngốn multi-GiB, bị OOM-kill trên Zig 0.13.0).
