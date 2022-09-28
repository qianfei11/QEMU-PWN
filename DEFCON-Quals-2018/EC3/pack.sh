#!/bin/bash

musl-gcc exp.cc -o exp -static -O2

cd fs/ && cp ../exp . && find ./* | cpio -H newc -o > ../fs.cpio && cd ../

gzip fs.cpio

