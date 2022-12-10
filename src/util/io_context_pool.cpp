#include "util/io_context_pool.h"

io_context_pool::io_context_pool(size_t pool_size) : next_io_context(0) {
    if (pool_size == 0) pool_size = 1;

    for (size_t i = 0; i < pool_size; ++i) {
        io_context_ptr io_context(std::make_shared<asio::io_context>());
        io_contexts.emplace_back(io_context);
        work.emplace_back(asio::make_work_guard(*io_context));
    }
}

void io_context_pool::run() {
    std::vector<std::shared_ptr<std::thread>> threads;
    for (size_t i = 0; i < io_contexts.size(); ++i) {
        threads.emplace_back(std::make_shared<std::thread>(
            [](io_context_ptr ptr) { ptr->run(); }, io_contexts[i]));
    }

    for (size_t i = 0; i < threads.size(); ++i) {
        threads[i]->join();
    }
}

void io_context_pool::stop() {
    for (size_t i = 0; i < io_contexts.size(); ++i) {
        io_contexts[i]->stop();
    }
}

asio::io_context& io_context_pool::get_io_context() {
    asio::io_context& io_context = *io_contexts[next_io_context];
    ++next_io_context;
    if (next_io_context == io_contexts.size()) {
        next_io_context = 0;
    }
    return io_context;
}