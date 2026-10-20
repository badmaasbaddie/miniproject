#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
rm -rf bin && mkdir -p bin
javac -d bin $(find src -name '*.java')
echo "[SUCCESS] Compiled into 'bin'. Run ./run.sh to start the website."
