FROM ubuntu:20.04
MAINTAINER xukeawsl xukeawsl@gmail.com

ADD . /home

WORKDIR /home

RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list
RUN apt-get update && apt-get install -y g++ && \
    apt-get install -y cmake

RUN [ -d "./build" ] && rm ./build -r
RUN mkdir build && cd build && cmake .. && make

CMD /bin/bash -c "./bin/socks_server"
