# Socks5 代理服务器

## 使用
* 下载仓库并创建构建目录
```bash
git clone https://github.com/xukeawsl/socks-server.git
mkdir build
cd build
```
* 构建 (默认 Debug)
```bash
# Linux
cmake ..
cmake --build .

# Windows
cmake -G "MinGW Makfiles" ..
cmake --build .

# 构建 Release(Linux)
cmake -DCMAKE_BUILD_TYPE=Release ..
```

## 调整日志级别
* 通过 cmake 的 `LOG_LEVEL` 选项调整日志等级
```bash
# 支持 Trace, Debug, Info, Warn, Error, Critical, Off
cmake -DLOG_LEVEL=Info ..

# Release 和 Debug 构建默认的日志等级分别是 Info 和 Debug
```

## TODO
* 支持 socks-server 命令行选项
* 完善功能和日志
