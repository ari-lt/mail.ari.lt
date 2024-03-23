#!/usr/bin/env sh

set -eu

main() {
    python3 -m pip install --upgrade gunicorn
    python3 -m gunicorn -b 127.0.0.1:13912 main:app &
    disown
}

main "$@"
