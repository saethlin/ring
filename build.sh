#!/bin/bash

aarch64-linux-gnu-gcc sha256-armv8-linux64.S -I include/ -c -o sha256-armv8-linux64.o 
aarch64-linux-gnu-ar rcs libring-core.a sha256-armv8-linux64.o 
RUSTFLAGS="-Ccodegen-units=1024" cargo b --release --target=aarch64-unknown-linux-gnu
