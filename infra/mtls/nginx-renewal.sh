#!/bin/sh
set -eu
nginx -t -c /config/all-hops.conf
nginx -c /config/all-hops.conf -g 'daemon off;' &
service_pid=$!
trap 'kill -TERM "$service_pid" 2>/dev/null || true' TERM INT EXIT
previous=''
while kill -0 "$service_pid" 2>/dev/null; do
    digest=$(cat /service-tls/proxy.pem /service-tls/proxy-auth.pem /service-tls/proxy-resource.pem | sha256sum | cut -d ' ' -f 1)
    if [ "$digest" != "$previous" ]; then
        if nginx -t -c /config/all-hops.conf && nginx -s reload -c /config/all-hops.conf; then
            printf '%s\n' "$digest" > /reload/ack.new
            mv /reload/ack.new /reload/ack
            previous=$digest
        fi
    fi
    sleep 0.2
done
wait "$service_pid"
