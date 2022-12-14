# Socks5 代理服务器

[![License](https://img.shields.io/npm/l/mithril.svg)](https://github.com/xukeawsl/socks-server/blob/master/LICENSE)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/d9a5e55fbad64d51886964bf0f9977c9)](https://www.codacy.com/gh/xukeawsl/socks-server/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=xukeawsl/socks-server&amp;utm_campaign=Badge_Grade)
[![Stars](https://img.shields.io/github/stars/xukeawsl/socks-server)](https://github.com/xukeawsl/socks-server)
[![Release](https://img.shields.io/github/v/release/xukeawsl/socks-server?color=red)](https://github.com/xukeawsl/socks-server/releases)
[![RepoSize](https://img.shields.io/github/repo-size/xukeawsl/socks-server?color=yellow)](https://img.shields.io/github/repo-size/xukeawsl/socks-server?color=yellow)

## 特性
* 无认证模式
* 用户名/密码认证模式
* 支持 `CONNECTION` 和 `UDP ASSOCIATE` 命令
* 支持通过 `IPV4(6)/域名` 访问远程机器

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
* 通过修改 `config.json` 文件内容进行服务器参数配置
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
    "supported-methods" : [0, 2],
    "timeout" : 60
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
5. `timeout` 配置连接的超时时间（默认为 `10` 分钟，单位为 `s`）

## docker-compose 部署
* 在 `docker-compose.yml` 所在目录下执行如下命令即可在后台自动部署服务
```bash
docker-compose up -d
```

## Valgrind 内存检测
* 检测程序是否存在内存泄漏：`valgrind --leck-check=full ../bin/socks-server`
```valgrind
==4706== HEAP SUMMARY:
==4706==     in use at exit: 0 bytes in 0 blocks
==4706==   total heap usage: 47,865 allocs, 47,865 frees, 21,989,332 bytes allocated
==4706== 
==4706== All heap blocks were freed -- no leaks are possible
==4706== 
==4706== For lists of detected and suppressed errors, rerun with: -s
==4706== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

## Benchmark 压力测试
* 测试机器 : `AMD EPYC 7K62 48-Core @ 2.6 GHz`
* 测试工具使用 https://github.com/cnlh/benchmark
* 使用 cinatra 库在本地搭建 ping-pong 测试服务器 https://github.com/qicosmos/cinatra
```cpp
#include "cinatra.hpp"
using namespace cinatra;

int main() {
    http_server server(std::thread::hardware_concurrency());
    server.listen("127.0.0.1", "80");

    server.set_http_handler<GET, POST>("/ping", [](request& req, response& res) {
		res.set_status_and_content(status_type::ok, "pong");
	});

    server.run();
	return 0;
}
```
* 添加本地域名解析 `vim /etc/hosts`
```bash
127.0.0.1 www.test.com
```

* 测试结果 : `QPS 8w+`
```bash
# 为了对比,同时测试了不通过 socks5 代理的 qps

# 单核 10w 次请求
# -------------------------------
# Requests/sec: 74880.03
./benchmark -n 100000 -proxy socks5://127.0.0.1:1080 http://www.test.com/ping
# Requests/sec: 175591.98
./benchmark -n 100000 http://www.test.com/ping
# -------------------------------

# 单核 100w 次请求
# -------------------------------
# Requests/sec: 91743.10
./benchmark -n 1000000 -proxy socks5://127.0.0.1:1080 http://www.test.com/ping
# Requests/sec: 215867.61
./benchmark -n 1000000 http://www.test.com/ping
# -------------------------------

# 多核 100 并发连接 10w 请求
# -------------------------------
# Requests/sec: 127783.83
./benchmark -c 100 -n 100000 -proxy socks5://127.0.0.1:1080 http://www.test.com/ping
# Requests/sec: 258914.98
./benchmark -c 100 -n 100000 http://www.test.com/ping
# -------------------------------

# 多核 1k 并发连接 10w 请求
# -------------------------------
# Requests/sec: 81295.52
./benchmark -c 1000 -n 100000 -proxy socks5://127.0.0.1:1080 http://www.test.com/ping
# Requests/sec: 187864.41
./benchmark -c 1000 -n 100000  http://www.test.com/ping
# -------------------------------

# 多核 1w 并发连接 10w 请求
# -------------------------------
# Requests/sec: 48632.97
./benchmark -c 10000 -n 100000 -proxy socks5://127.0.0.1:1080 http://www.test.com/ping
# Requests/sec: 101979.19
./benchmark -c 10000 -n 100000 http://www.test.com/ping
# -------------------------------

# 多核 100 并发连接 100w 次请求
# -------------------------------
# Requests/sec: 115556.33
./benchmark -c 100 -n 1000000 -proxy socks5://127.0.0.1:1080 http://www.test.com/ping
# Requests/sec: 275821.31
./benchmark -c 100 -n 1000000 http://www.test.com/ping
# -------------------------------

# 多核 1k 并发连接 100w 次请求
# -------------------------------
# Requests/sec: 88920.73
./benchmark -c 1000 -n 1000000 -proxy socks5://127.0.0.1:1080 http://www.test.com/ping
# Requests/sec: 213493.31
./benchmark -c 1000 -n 1000000 http://www.test.com/ping
# -------------------------------

# 多核 1w 并发连接 100w 次请求
# -------------------------------
# Requests/sec: 69312.54
./benchmark -c 10000 -n 1000000 -proxy socks5://127.0.0.1:1080 http://www.test.com/ping
# Requests/sec: 124741.30
./benchmark -c 10000 -n 1000000 http://www.test.com/ping
# -------------------------------
```

## 参考文档
* [RFC1928 : SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/inline-errata/rfc1928.html)
* [RFC1929 : Username/Password Authentication for SOCKS V5](https://www.rfc-editor.org/rfc/rfc1929.html)

## TODO
* `UDP ASSOCIATE` 支持通提供过 `ipv6/域名` 访问远程机器
* 支持 `BIND` 命令
