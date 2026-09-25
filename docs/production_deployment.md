# SafeGGUF Production Deployment & Integration Guide

Tài liệu hướng dẫn triển khai thực tế công cụ kiểm định an toàn mô hình [**SafeGGUF**](https://github.com/BrianNguyen29/SafeGGUF) trong các môi trường doanh nghiệp (Inference Gateways, Kubernetes Pods, vLLM / Ollama clusters, và môi trường mạng biệt lập Air-gapped).

---

## 1. Kiến Trúc Cổng Phòng Thủ Tiền Nạp (Pre-Admission Firewall)

SafeGGUF đóng vai trò là chốt chặn bảo mật đầu vào tại tầng Ingress trước khi bất kỳ byte dữ liệu hoặc trọng số tensor nào được `mmap` vào tiến trình suy luận (`llama.cpp`, `vLLM`, `Ollama`).

```
                              KIẾN TRÚC INGRESS TOÀN DIỆN
                              
   [ Model Ingestion: HuggingFace / S3 / S3-compatible / Local Upload ]
                                     |
                                     v
   +-------------------------------------------------------------------+
   | TẦNG 1: SafeGGUF Deterministic Pre-Admission Filter               |
   | - Kiểm tra Checked Arithmetic (Chống tràn số 64-bit)              |
   | - Khống chế QuotaAllocator (128 MB) & WorkBudget (10M units)      |
   | - Rà soát Alignment Padding 256-byte (Chống mã độc steganography) |
   | - Sliding Window 64 KiB: Tiêu thụ I/O streaming có giới hạn với QuotaAllocator ceiling 128 MB, độ trễ < 10ms |
   +-------------------------------------------------------------------+
                     /                               \
        Exit Code 2 /                                 \ Exit Code 0
                   /                                   \
                  v                                     v
   +------------------------------+     +-------------------------------+
   | 🚫 HARD REJECT (DROP)        |     | TẦNG 2: Downstream Admission  |
   | - Chặn ngay tại cửa khẩu     |     | - safegguf-triage / Policy    |
   | - Không cấp phát bộ nhớ      |     +-------------------------------+
   | - Bắn cảnh báo SIEM / SOC    |                 /       \
   +------------------------------+   Risk: Low   /         \ Risk: High
                                                 /           \
                                                v             v
                                        +-------------+  +---------------+
                                        | ✅ PROD POD |  | ⚠️ QUARANTINE |
                                        | (Admit)     |  | (Investigation)
                                        +-------------+  +---------------+
```

---

## 2. Triển Khai CLI & Cấu Hình Biến Môi Trường

### 2.1. Lệnh Thực Thi Chuẩn Cho Production
Luôn cấu hình cờ `--profile llama-cpp` cho các hệ thống phục vụ `llama.cpp` và bật `--endian auto`:

```bash
# Chế độ Text hiển thị dòng lệnh
safegguf inspect /path/to/model.gguf --profile llama-cpp --endian auto

# Chế độ JSON cho máy tính / Logging Pipeline
safegguf inspect /path/to/model.gguf --profile llama-cpp --endian auto --format json
```

### 2.2. Bảng Exit Codes Chuẩn Định
| Mã Thoát | Ý nghĩa | Hành Động Vận Hành |
| :---: | :--- | :--- |
| **`0`** | **PASS** | Tệp vượt qua thẩm định cấu trúc & số học (STRUCTURALLY_ACCEPTED) $\rightarrow$ Bàn giao cho tầng chính sách nạp (admission policy). |
| **`2`** | **REJECT** | Phát hiện vi phạm cấu trúc, tràn số, hoặc vượt quota $\rightarrow$ Hủy tệp ngay lập tức. |
| **`64`** | **EX_USAGE** | Sai tham số dòng lệnh $\rightarrow$ Kiểm tra lại cấu hình gọi lệnh. |
| **`70`** | **EX_SOFTWARE** | Lỗi nội bộ hoặc host cạn kiệt RAM vật lý $\rightarrow$ Khởi động lại container. |
| **`74`** | **EX_IOERR** | Không mở được tệp, không đọc được dữ liệu $\rightarrow$ Kiểm tra quyền đọc và ổ đĩa. |

### 2.3. Cấu Hình Tài Nguyên Linh Hoạt (Environment Variables)
Khi chạy trên các máy chủ có cấu hình đặc thù, bạn có thể điều chỉnh trần tài nguyên qua biến môi trường mà không cần biên dịch lại:
```bash
# Trần bộ nhớ cấp phát tối đa cho validator (mặc định 128 MB)
export SAFEGGUF_MAX_ALLOC_BYTES=268435456 # 256 MiB

# Trần số đơn vị công việc logic tối đa (mặc định 10,000,000 đơn vị)
export SAFEGGUF_MAX_WORK_UNITS=20000000

# Trần số byte tối đa được phép quét qua reader (mặc định 256 MiB)
export SAFEGGUF_MAX_SCANNED_BYTES=536870912 # 512 MiB
```

---

## 3. Tích Hợp Python In-Process Chống Tấn Công TOCTOU

Để loại bỏ hoàn toàn độ trễ khởi động tiến trình con (fork-exec) và ngăn chặn tấn công tráo đổi tệp giữa thời điểm kiểm tra và nạp (**Time-Of-Check to Time-Of-Use**), hãy sử dụng thư viện Python Binding chính thức:

### 3.1. Cài đặt Python Binding
```bash
cd bindings/python
pip install .
```

### 3.2. Mẫu Code Xác Thực An Toàn qua File Descriptor
```python
import os
import safegguf

# Mở tệp ở chế độ Read-Only duy nhất một lần
fd = os.open("/models/untrusted_model.gguf", os.O_RDONLY)
try:
    # 1. Xác thực trực tiếp trên File Descriptor đã mở (Không truyền đường dẫn chuỗi)
    result = safegguf.validate_fd(fd, profile="llama-cpp", endian="auto")
    
    if not result.is_valid:
        raise SecurityError(f"Model bị từ chối bởi SafeGGUF! Exit code: {result.exit_code}")
    
    print("Model vượt qua kiểm định cấu trúc! Bàn giao file descriptor cho downstream policy/runtime...")
    # 2. Bàn giao trực tiếp file descriptor cho C++ runtime qua mmap
    # run_inference_engine(fd)
finally:
    os.close(fd)
```

---

## 4. Triển Khai Kubernetes Cloud-Native & Anti-TOCTOU Handoff

Mẫu Pod Deployment trong Kubernetes áp dụng mô hình InitContainer 2 giai đoạn với chốt chặn mật mã Content-Hash Handoff (xem chi tiết tại [`deploy/k8s/safegguf-initcontainer.yaml`](../deploy/k8s/safegguf-initcontainer.yaml) và [`deploy/k8s/attestation_handoff.sh`](../deploy/k8s/attestation_handoff.sh)):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: llama-serving-pod
spec:
  volumes:
    - name: model-storage
      persistentVolumeClaim:
        claimName: models-pvc
    - name: attestation-storage
      emptyDir:
        medium: Memory
  initContainers:
    # Giai đoạn 1: Thẩm định cấu trúc và số học với SafeGGUF (Fail-closed exit 2)
    - name: safegguf-validator
      image: ghcr.io/briannguyen29/safegguf:v0.3.7-dev
      command: ["/usr/local/bin/safegguf", "inspect", "/models/model.gguf", "--profile", "llama-cpp", "--format", "json", "--endian", "auto"]
      volumeMounts:
        - name: model-storage
          mountPath: /models
          readOnly: true
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532

    # Giai đoạn 2: Tạo attestation digest SHA-256 vào volume bộ nhớ tạm (CAS)
    - name: safegguf-attestation-generator
      image: busybox:1.36-musl
      command: ["/bin/sh", "-c", "sha256sum /models/model.gguf > /attestation/model.gguf.sha256"]
      volumeMounts:
        - name: model-storage
          mountPath: /models
          readOnly: true
        - name: attestation-storage
          mountPath: /attestation
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65534

  containers:
    # Tầng Inference Runtime: Đối soát attestation hash trước khi mmap trọng số
    - name: llama-cpp-server
      image: ghcr.io/ggerganov/llama.cpp:server
      command:
        - /bin/sh
        - -c
        - |
          set -euo pipefail
          echo "[Inference Gate] Validating cryptographic attestation..."
          sha256sum -c /attestation/model.gguf.sha256
          exec /server -m /models/model.gguf -c 4096 --host 0.0.0.0 --port 8080
      volumeMounts:
        - name: model-storage
          mountPath: /models
          readOnly: true
        - name: attestation-storage
          mountPath: /attestation
          readOnly: true
```
> **Đặc tính Fail-Closed & Anti-TOCTOU**: Nếu tệp model bị lỗi hoặc độc hại, container `safegguf-validator` sẽ thoát với mã `exit 2`, ngăn chặn toàn bộ Pod khởi động. Nếu tệp model bị tráo đổi sau khi kiểm tra, bước `sha256sum -c` tại container serving sẽ phát hiện sai lệch và từ chối tải trọng số vào bộ nhớ.

---

## 5. Vận Hành Triage: Online Jev vs Offline Air-Gapped Fallback

Sử dụng công cụ `safegguf-triage` ([`tools/safegguf-triage/safegguf_triage.py`](file:///C:/Users/Duong%20Nguyen/.gemini/antigravity/scratch/safegguf_test/tools/safegguf-triage/safegguf_triage.py)):

### 5.1. Khi Có Kết Nối Mạng & TypeSafe API Key
```bash
export TYPESAFE_API_KEY="ts_live_..."
python tools/safegguf-triage/safegguf_triage.py /models/model.gguf --format json
```
* Engine: **Online Jev System One**
* Trả về điểm số rủi ro ngữ nghĩa (`risk_score`), phân loại mối đe dọa (`threat_category`), và phán quyết cấu trúc (`structural_verdict`).

### 5.2. Khi Chạy Trong Môi Trường Biệt Lập (Air-Gapped / Không có Jev)
```bash
# Không cần thiết lập TYPESAFE_API_KEY, công cụ tự động kích hoạt Offline Engine
python tools/safegguf-triage/safegguf_triage.py /models/model.gguf --mode offline
```
* Engine: **Offline Deterministic Rule Engine**
* **Đặc tính**: Tiêu tốn **0 ms độ trễ mạng**, **0 chi phí token**, tự động bóc tách mã lỗi SafeGGUF để chấm điểm rủi ro và khuyến nghị phán quyết (`STRUCTURALLY_ACCEPTED` vs `REJECT`).
