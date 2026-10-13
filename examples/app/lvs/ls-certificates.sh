#!/bin/sh
set -eu

cd "$(dirname "$0")"
pyndnsec --path . --tpm tpm-file --tpm-path privKeys ls -vvv
