FROM ubuntu:20.04

COPY . /home

WORKDIR /home

RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list

# Install Required Packages
RUN apt-get update && apt-get install -y g++ cmake

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN [ -d "./build" ] && rm ./build -r; echo ''
RUN mkdir build && cd build && cmake -DCMAKE_BUILE_TYPE=Release .. && make

CMD cd build && /bin/bash -c "../bin/socks_server"
