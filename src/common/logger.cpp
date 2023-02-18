#include "common/logger.h"

#include <cstdio>

Logger* Logger::getInstance() {
    static Logger logger;
    return &logger;
}

bool Logger::Init(const std::string& log_file, long unsigned max_rotateSize,
                  long unsigned max_rotateCount) {
    try {
        spdlog::init_thread_pool(8192, 1);
        auto console_sink =
            std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, max_rotateSize, max_rotateCount);
#ifndef NDEBUG
        spdlog::set_default_logger(std::make_shared<spdlog::async_logger>(
            "debug_logger", spdlog::sinks_init_list({console_sink, file_sink}),
            spdlog::thread_pool(),
            spdlog::async_overflow_policy::overrun_oldest));
#else    // Release
        spdlog::set_default_logger(std::make_shared<spdlog::async_logger>(
            "release_logger", file_sink, spdlog::thread_pool(),
            spdlog::async_overflow_policy::block));
#endif

        switch (SPDLOG_ACTIVE_LEVEL) {
            case SPDLOG_LEVEL_TRACE:
                spdlog::set_level(spdlog::level::trace);
                break;
            case SPDLOG_LEVEL_DEBUG:
                spdlog::set_level(spdlog::level::debug);
                break;
            case SPDLOG_LEVEL_INFO:
                spdlog::set_level(spdlog::level::info);
                break;
            case SPDLOG_LEVEL_WARN:
                spdlog::set_level(spdlog::level::warn);
                break;
            case SPDLOG_LEVEL_ERROR:
                spdlog::set_level(spdlog::level::err);
                break;
            case SPDLOG_LEVEL_CRITICAL:
                spdlog::set_level(spdlog::level::critical);
                break;
            case SPDLOG_LEVEL_OFF:
                spdlog::set_level(spdlog::level::off);
                break;
            default:
                break;
        }

        spdlog::set_pattern("[%Y-%m-%d %T.%f] [%^%l%$] [thread %t] %v");

    } catch (const spdlog::spdlog_ex& ex) {
        std::printf("Logger Init Failed");
        return false;
    }
    return true;
}