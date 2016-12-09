#!/bin/sh
set -e
if [ ! -d "$HOME/cmake-3.7.1/bin" ]; then
    wget --no-check-certificate https://cmake.org/files/v3.7/cmake-3.7.1.tar.gz
    tar zxf cmake-3.7.1.tar.gz
    cd cmake-3.7.1 && ./configure --prefix=$HOME/cmake-3.7.1 && \
        make && make install
else
    echo "Using cached cmake"
fi
