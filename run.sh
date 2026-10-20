#!/usr/bin/env bash
cd "$(dirname "$0")"
echo "Starting Password Security Suite at http://localhost:8080/ (Ctrl+C to stop)"
java -cp bin passwordsecurity.Main "$@"
