SRC_DIRS := $(shell find src -maxdepth 3 -type d)
SRCS = $(foreach dir, $(SRC_DIRS), $(wildcard $(dir)/*.cpp))
INC_DIRS := $(shell find include -maxdepth 3 -type d)
INCS = $(foreach dir, $(INC_DIRS), $(wildcard $(dir)/*.h))

format:
	@clang-format --style=file $(INCS) $(SRCS) main.cpp -i

check:
	@cd build && \
	valgrind --log-file=memcheck.log --tool=memcheck --leak-check=full \
	../bin/socks_server