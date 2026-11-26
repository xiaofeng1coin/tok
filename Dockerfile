# 构建阶段：编译 unicorn2 静态库和 Go 签名服务
FROM golang:1.24-bookworm AS builder

ENV CGO_ENABLED=1 \
    GOFLAGS=-buildvcs=false

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates cmake git make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
# replace 指向本地 third_party，下载依赖前必须先把该模块放进去。
COPY third_party/ ./third_party/
RUN go mod download

COPY . .

# 只构建 ARM64 目标的 unicorn2；静态库直接链接进 Go 程序，运行镜像无需带 so。
RUN git clone --depth 1 --branch 2.1.4 https://github.com/unicorn-engine/unicorn.git /tmp/unicorn && \
    cmake -S /tmp/unicorn -B /tmp/unicorn/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      -DUNICORN_LEGACY_STATIC_ARCHIVE=ON \
      -DUNICORN_BUILD_TESTS=OFF \
      -DUNICORN_ARCH=aarch64 && \
    cmake --build /tmp/unicorn/build --parallel "$(nproc)" && \
    cmake --install /tmp/unicorn/build

RUN CGO_CFLAGS="-I/usr/local/include" \
    CGO_LDFLAGS="-L/usr/local/lib -lunicorn -lpthread -lm" \
    WTOKEN_ALLOW_REPORT_NETWORK=0 \
    go test ./... github.com/wnxd/microdbg/internal/debugger github.com/wnxd/microdbg-android/internal/10 && \
    CGO_CFLAGS="-I/usr/local/include" \
    CGO_LDFLAGS="-L/usr/local/lib -lunicorn -lpthread -lm" \
    go build -trimpath -ldflags "-s -w" -o /out/wtoken-server .

# 运行阶段：只带程序、裁剪 APK 和 Android 10 运行时镜像
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /out/wtoken-server /app/wtoken-server
COPY apk/yongpai.apk /app/apk/yongpai.apk
COPY runtime/10.zip /app/runtime/10.zip

ENV PORT=4097 \
    APK_PATH=/app/apk/yongpai.apk \
    RUNTIME_DIR=/app/runtime/10.zip

EXPOSE 4097
USER 65534:65534
CMD ["/app/wtoken-server"]
