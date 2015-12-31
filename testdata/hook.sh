#!/bin/sh
# Simulate the update-haproxy.sh behavior, for tests; but also writes to stderr.
cat >/dev/null
echo "OCSP Response updated!"
echo -n "script successfully called" 1>&2
