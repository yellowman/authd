#!/bin/sh
set -eu

# 32 random bytes, standard base64. Keep the result out of the repository.
if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32
else
    dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64
fi
