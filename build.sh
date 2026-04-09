#!/bin/bash

mkdir -p build
cd build
rm -rf *
cmake ../ -DDEBUG_LOGS=ON
make -j4
