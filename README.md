# Socks5 代理服务器

## 使用
* 下载仓库并创建构建目录
```bash
git clone https://github.com/xukeawsl/socks-server.git
mkdir build
cd build
```
* 构建 (默认 Deubug)
```bash
# Linux
cmake ..
cmake --build .

# Windows
cmake -G "MinGW Makfiles" ..
cmake --build .

# 构建 Release
cmake -DCMAKE_BUILD_TYPE=Release ..
```
