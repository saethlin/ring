#!/bin/bash

set -e

cc ring-core.c -c -o ring-core.o
ar rcs libring-core.a ring-core.o
RUSTFLAGS="-Ccodegen-units=2" cargo b --release
