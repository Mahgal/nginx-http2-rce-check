#!/bin/sh
# Fixture nginx binary (NOT a real nginx): prints a real-format `nginx -v`
# for a PATCHED build, to stderr, and exits 0.
# Use it to try --nginx-path on a machine without nginx installed:
#   python3 nginx_http2_check.py --nginx-path examples/fake-nginx-patched.sh --config examples/nginx-http2-on.conf
echo 'nginx version: nginx/1.30.7' >&2
