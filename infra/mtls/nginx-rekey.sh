#!/bin/sh
set -eu
configuration=/service-tls/nginx-rekey.conf
nginx -t -c "$configuration"
nginx -c "$configuration" -g 'daemon off;' &
service_pid=$!
trap 'kill -TERM "$service_pid" 2>/dev/null || true' TERM INT EXIT
previous=''
while kill -0 "$service_pid" 2>/dev/null; do
    digest=$({ cat "$configuration"; grep -oE '/service-tls/[A-Za-z0-9_-]+\.(pem|key)' "$configuration" | sort -u | xargs cat; } | sha256sum | cut -d ' ' -f 1)
    if [ "$digest" != "$previous" ]; then
        if nginx -t -c "$configuration" && nginx -s reload -c "$configuration"; then
            printf '%s\n' "$digest" > /reload/ack.new
            mv /reload/ack.new /reload/ack
            previous=$digest
        fi
    fi
    sleep 0.2
done
wait "$service_pid"
