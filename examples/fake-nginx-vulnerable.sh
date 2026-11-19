#!/bin/sh
# Fixture nginx binary (NOT a real nginx): prints a real-format `nginx -v`
# for an AFFECTED build, to stderr, and exits 0.
# Use it to try --nginx-path on a machine without nginx installed:
#   python3 nginx_http2_check.py --nginx-path examples/fake-nginx-vulnerable.sh --config examples/nginx-http2-on.conf
echo 'nginx version: nginx/1.31.8' >&2
