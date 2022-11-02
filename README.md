# Socks5 代理服务器

[![License](https://img.shields.io/npm/l/mithril.svg)](https://github.com/xukeawsl/socks-server/blob/master/LICENSE)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/d9a5e55fbad64d51886964bf0f9977c9)](https://www.codacy.com/gh/xukeawsl/socks-server/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=xukeawsl/socks-server&amp;utm_campaign=Badge_Grade)
[![Stars](https://img.shields.io/github/stars/xukeawsl/socks-server)](https://github.com/xukeawsl/socks-server)
[![Release](https://img.shields.io/github/v/release/xukeawsl/socks-server?color=red)](https://github.com/xukeawsl/socks-server/releases)
[![RepoSize](https://img.shields.io/github/repo-size/xukeawsl/socks-server?color=yellow)](https://img.shields.io/github/repo-size/xukeawsl/socks-server?color=yellow)

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

## 配置服务器参数
```json
{
    "server" : {
        "host" : "127.0.0.1",
        "port" : 1080
    },
    "log" : {
        "log_file" : "logs/server.log",
        "max_rotate_size" : 1048576,
        "max_rotate_count" : 10
    },
    "auth" : {
        "username" : "socks-user",
        "password" : "socks-passwd"
    },
    "supported-methods" : [0, 2]
}
```

1. `server` 配置服务器相关参数
   * `host` ：监听的 ip 地址（默认 `127.0.0.1` ）
   * `port` ：监听的端口号（默认 `1080` ）
   * `thread_num` ：后台工作线程个数（默认为 cpu 核心数）

2. `log` 配置日志文件相关参数
   * `log_file` ：日志文件的路径（相对路径是基于构建目录的，默认为 `logs/server.log`）
   * `max_rotate_size` ：单个滚动日志文件的最大大小（默认为 1MB）
   * `max_rotate_count` ：最大滚动日志文件个数（默认10个）

3. `auth` 配置代理服务器认证的用户名/密码
   * `username` ：用户名(需要认证则必填)
   * `password` ：密码(需要认证则必填)

4. `supported-methods` 配置代理服务器支持的认证方法
   * `0` : 不需要认证
   * `2` : 需要用户名/密码认证

## docker-compose 部署
```bash
docker-compose up -d
```

## Valgrind 内存检测
* 检测程序是否存在内存泄漏：`valgrind --leck-check=full ../bin/socks-server`
```valgrind
==9516== HEAP SUMMARY:
==9516==     in use at exit: 0 bytes in 0 blocks
==9516==   total heap usage: 546 allocs, 546 frees, 4,461,344 bytes allocated
==9516== 
==9516== All heap blocks were freed -- no leaks are possible
==9516== 
==9516== For lists of detected and suppressed errors, rerun with: -s
==9516== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

## TODO
* 完善功能
* benchmark
