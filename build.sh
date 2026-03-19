#!/bin/bash

# ===============================================
# GoPhantom 多平台交叉编译脚本
# 使用方法: ./build.sh [版本号]
# 示例: ./build.sh v1.5
# ===============================================

set -e

# 版本号（可通过参数指定，默认读取 VERSION 文件或使用 dev）
if [ -n "$1" ]; then
    VERSION="$1"
elif [ -f "VERSION" ] && [ -s "VERSION" ]; then
    VERSION=$(cat VERSION)
else
    VERSION="dev"
fi

# 编译参数
LDFLAGS="-s -w"
SOURCE="generator.go"
OUTPUT_DIR="dist"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

echo "============================================="
echo "GoPhantom 多平台编译脚本"
echo "版本: ${VERSION}"
echo "============================================="
echo ""

# Windows x64
echo "[1/4] 编译 Windows x64..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "${OUTPUT_DIR}/GoPhantom-${VERSION}-windows-amd64.exe" $SOURCE

# Linux x64
echo "[2/4] 编译 Linux x64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "${OUTPUT_DIR}/GoPhantom-${VERSION}-linux-amd64" $SOURCE

# macOS Intel
echo "[3/4] 编译 macOS Intel..."
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "${OUTPUT_DIR}/GoPhantom-${VERSION}-darwin-amd64" $SOURCE

# macOS Apple Silicon
echo "[4/4] 编译 macOS Apple Silicon..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "${OUTPUT_DIR}/GoPhantom-${VERSION}-darwin-arm64" $SOURCE

echo ""
echo "============================================="
echo "编译完成！生成的文件："
echo "============================================="
ls -lh "${OUTPUT_DIR}"/GoPhantom-${VERSION}*

echo ""
echo "文件说明："
echo "  GoPhantom-${VERSION}-windows-amd64.exe  - Windows x64"
echo "  GoPhantom-${VERSION}-linux-amd64        - Linux x64"
echo "  GoPhantom-${VERSION}-darwin-amd64       - macOS Intel"
echo "  GoPhantom-${VERSION}-darwin-arm64       - macOS Apple Silicon"
echo ""
echo "输出目录: ${OUTPUT_DIR}/"
