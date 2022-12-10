#pragma once

#include "common/common.h"

class io_context_pool : private noncopyable {
public:
    explicit io_context_pool(size_t pool_size);

    void run();

    void stop();

    asio::io_context& get_io_context();

private:
    using io_context_ptr  = std::shared_ptr<asio::io_context>;
    using io_context_work = asio::executor_work_guard<
        asio::io_context::executor_type>;

    std::vector<io_context_ptr> io_contexts;
    std::list<io_context_work> work;

    size_t next_io_context;
};