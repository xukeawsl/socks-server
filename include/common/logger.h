#pragma once

#include "spdlog/spdlog.h"
#include "spdlog/async.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/basic_file_sink.h"

#define DEBUG

class Logger {
public:
    static Logger* getInstance() {
        static Logger logger;
        return &logger;
    }

    bool Init(const std::string& log_file = "logs/log.txt",
            long unsigned max_rotateSize = 1024 * 1024 * 10,
            long unsigned max_rotateCount = 10) {
        try {
            spdlog::init_thread_pool(8192, 1);
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(log_file,
                                                                                max_rotateSize,
                                                                                max_rotateCount);                           
            #ifdef DEBUG
            spdlog::set_default_logger(std::make_shared<spdlog::async_logger>("debug_logger",
                                       spdlog::sinks_init_list({console_sink, file_sink}),
                                       spdlog::thread_pool(),
                                       spdlog::async_overflow_policy::overrun_oldest));
            #else // Release
            spdlog::set_default_logger(std::make_shared<spdlog::async_logger>("release_logger",
                                        file_sink,
                                        spdlog::thread_pool(),
                                        spdlog::async_overflow_policy::block));
            #endif
            spdlog::info("debug");
        } catch(const spdlog::spdlog_ex& ex) {
            std::cout << "Logger Init Failed" << std::endl;
            return false;
        }
        return true;
    }

private:
    Logger() = default;
    ~Logger() { spdlog::shutdown(); }
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;
};