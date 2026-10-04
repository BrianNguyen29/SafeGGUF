# SafeGGUF: triển khai và tích hợp production

SafeGGUF kiểm tra cấu trúc, số học và chính sách tài nguyên của GGUF trước khi
runtime đọc model. PASS không chứng minh nguồn gốc, hành vi an toàn hay khả năng
chạy suy luận. Dùng thêm chính sách nguồn gốc và kiểm thử runtime của dịch vụ.

## 1. Chọn giao diện

- `inspect`: lấy phán quyết, diagnostics và metrics; mặc định llama-cpp + auto.
- `validate_fd`: kiểm tra inode đã mở trong tiến trình gọi. Giữ descriptor sống
  và bảo vệ nội dung inode khỏi writer trong suốt kiểm tra và sử dụng.
- `admit`: sao chép nguồn vào staging riêng, băm trong lúc sao chép, kiểm tra
  cùng inode rồi xuất bản model và attestation. Đây là luồng bàn giao được khuyến
  nghị khi nguồn tải lên có thể thay đổi.

Không chạy inspect rồi băm lại đường dẫn upload có thể bị sửa. Script
[attestation_handoff.sh](../deploy/k8s/attestation_handoff.sh) gọi trực tiếp admit,
không có một triển khai kiểm tra/băm/xuất bản thứ hai.

## 2. Kiểm tra CLI

```bash
safegguf inspect /path/to/model.gguf --profile llama-cpp --endian auto --format json
safegguf inspect /path/to/model.gguf --emit-metrics --log-json --request-id req-123
```

| Exit | Ý nghĩa | Cách xử lý |
| --- | --- | --- |
| 0 | PASS theo profile và ngân sách đã chọn | Chuyển sang bước admission/runtime tiếp theo. |
| 2 | Vi phạm cấu trúc/số học/chính sách tài nguyên | Không nạp; lưu diagnostics để triage. |
| 64 | Sai cách gọi hoặc options | Sửa cấu hình gọi chương trình. |
| 70 | Lỗi nội bộ hoặc host OOM | Giữ ingress đóng và điều tra tài nguyên/crash. |
| 74 | Lỗi mở/stat/đọc/xuất bản | Giữ ingress đóng và kiểm tra storage/quyền. |

Dùng canonical_error_code để xây dựng quy tắc xử lý lỗi. Profile llama-cpp từ
chối tên tensor chứa NUL để tránh khác biệt định danh với chuỗi C của upstream.
Profile gguf-spec là lựa chọn riêng, không thay thế bảo đảm tương thích runtime.

## 3. Xuất bản bằng admit

Chuẩn bị thư mục riêng do service quản lý, không cho uploader hoặc tiến trình
không đáng tin có quyền ghi. Với thư mục mới do chính service tạo:

```bash
umask 077
mkdir -p /srv/safegguf/validated /srv/safegguf/attestations
safegguf admit /uploads/model.gguf \
  --cas-dir /srv/safegguf/validated \
  --attestations-dir /srv/safegguf/attestations \
  --profile llama-cpp --endian auto \
  --max-file-size-bytes 17179869184 > admission.json
```

Chỉ tiếp tục sau exit 0. Model nằm tại CAS_DIR/digest; attestation và checksum
pin nằm tại ATTESTATIONS_DIR/digest.json và digest.sha256. Thành công stdout
trùng byte với document lưu trên đĩa. Đọc cas.relative_path tương đối từ CAS_DIR,
kiểm tra SHA-256 và kích thước, rồi nạp object từ storage không còn untrusted writer.

Attestation schema v2 ghi tất cả limits hiệu lực, key_policy, endian yêu cầu
và đã giải quyết, profile và build/type-table provenance. Kiểm tra chính sách
trong document trước khi tiếp nhận; dữ liệu từng PASS với lenient có thể bị
strict từ chối. Schema diagnostics của inspect/error vẫn là v1.
Xem [hợp đồng và migration](admission-attestation.md).

REJECT không xuất bản dữ liệu của lượt đó. Lỗi sau khi rename object có thể
để lại object/document chưa đủ bộ; exit 74 không được xem như admission thành
công. CAS, statement và pin không phải một giao dịch filesystem duy nhất.

## 4. Giới hạn tài nguyên và quyền

Ngân sách mặc định: cấp phát do validator quản lý 128 MiB, 10 triệu đơn vị công
việc và 256 MiB quét chuỗi/UTF-8/bool. admit có trần file mặc định 16 GiB.
CLI options ghi đè môi trường; malformed environment values bị bỏ qua, vì vậy
deployment cần xác thực cấu hình của chính nó.

```bash
export SAFEGGUF_MAX_ALLOC_BYTES=134217728
export SAFEGGUF_MAX_WORK_UNITS=10000000
export SAFEGGUF_MAX_SCANNED_BYTES=268435456
```

Đặt giới hạn OS/container cho RSS, CPU, thời gian, dung lượng staging và file
đầu vào. Các ngân sách parser không giới hạn toàn bộ thao tác sao chép/băm của
admit. Không có SLA độ trễ cố định: đo bằng benchmark và workload thực tế.

File descriptor giữ danh tính inode, không làm bytes bất biến. FileIdentity
là phép so metadata trước/sau, không phải cơ chế niêm phong mật mã. Mode 0444
không ngăn owner chmod hoặc writer thay thế đường dẫn trong thư mục. Giữ riêng
quyền writer của service và mount read-only cho serving. Xác thực/chữ ký model
và admission statement thuộc chính sách của operator.

## 5. Python và C ABI

Build bằng Zig 0.13.0 rồi đóng gói wheel:

```bash
zig build -Doptimize=ReleaseSafe
python3 -m pip wheel ./bindings/python --no-deps -w dist
```

Python validate_path/validate_fd dùng cùng lõi với CLI. Giao diện C v1 giữ các
layout options đã phát hành bằng struct_size; controls mà native library cũ
không thực thi được bị từ chối. Chuỗi trả từ canonical error-code API thuộc
static storage của library, không phụ thuộc vòng đời buffer của caller.

Khi dùng validate_fd, downstream cần dùng cùng descriptor hoặc một CAS object
được bảo vệ. Chỉ truyền descriptor qua API không đủ để chống writer sửa inode.

## 6. Kubernetes

[Manifest](../deploy/k8s/safegguf-initcontainer.yaml) là template. Workflow
container release sinh bản đã render từ digest ảnh vừa ký. Không apply template
chưa render hoặc tự đặt digest của ảnh chưa phát hành.

Luồng: init chuẩn bị thư mục → init admit → serving kiểm tra đúng một checksum
pin rồi nạp model theo digest. Init admission là tiến trình duy nhất sao chép,
băm và kiểm tra model. Serving không mount upload và mount CAS/attestation
read-only. Các container chạy nonroot, capabilities bị bỏ và seccomp được bật.

Renderer offline kiểm tra version/digest và không ghi đè output cũ:

```bash
python3 scripts/render_k8s_manifest.py \
  --validator-image "$VERIFIED_RELEASE_IMAGE" \
  --version "$RELEASE_VERSION" \
  --output "safegguf-k8s-${RELEASE_VERSION}.yaml"
```

Operator phải xác minh chữ ký ảnh, cấu hình namespace/PVC/registry access và
controller/readiness cho serving. Pod example không có thời hạn một giờ:
activeDeadlineSeconds áp dụng cả thời gian phục vụ, không riêng admission.
Đặt admission timeout ở orchestration của môi trường thực tế.

## 7. Triage và kiểm chứng release

Triage chạy offline mặc định; chỉ mode online mới gọi API bên ngoài. Điểm số
từ diagnostics là phân loại theo quy tắc, không phải xác suất đã hiệu chỉnh
hay phân tích hành vi của weights. Không dùng Structural-Pass làm nhãn tin cậy.

Xem [release notes](release-notes-0.3.7.md)
và [SECURITY.md](../SECURITY.md). Chạy inference smoke trong môi trường thử nghiệm
đã xác định trước khi rollout production; các kiểm tra static/local không
thay thế CI đa nền tảng hay xác minh trên cluster thực tế.
