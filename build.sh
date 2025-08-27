#!/bin/bash
set -e

# 创建输出目录
mkdir -p build

# 编译ARM版本
echo "Building ARM (gnueabi)..."
arm-linux-gnueabi-gcc -O2 -marm -Wall ptbl.c -ldl -o build/ptbl -Wl,--export-dynamic

echo "Building ARM (gnueabihf)..."
arm-linux-gnueabihf-gcc -O2 -marm -Wall ptbl.c -ldl -o build/ptbl_hf -Wl,--export-dynamic

echo "Building MIPS..."
mips-linux-gnu-gcc -O2 -Wall ptbl.c -ldl -o build/ptbl_mips -Wl,--export-dynamic

# 检查二进制文件
echo "Build completed. Binary info:"
file build/ptbl*
echo "Binaries are in build/ directory"
