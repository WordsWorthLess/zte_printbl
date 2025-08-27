FROM ubuntu:22.04

# 安装编译工具链
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc-arm-linux-gnueabi \
    g++-arm-linux-gnueabi \
    gcc-arm-linux-gnueabihf \
    g++-arm-linux-gnueabihf \
    gcc-mips-linux-gnu \
    g++-mips-linux-gnu \
    binutils-mips-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

CMD ["./build.sh"]
