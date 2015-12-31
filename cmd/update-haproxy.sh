#!/bin/sh
echo "set ssl ocsp-response $(base64 -w 0)" | socat stdio /var/run/haproxy/admin.sock
