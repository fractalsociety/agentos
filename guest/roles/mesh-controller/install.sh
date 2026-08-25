#!/bin/sh
set -eu

ROLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=0.29.3
SOURCE_SHA=7289cf171176e7a6e3914763d1585b33020919caac23ed447fd9366347ba03c8
AMD64_SHA=cb44be5032bf3ba552cb868805825d416dbee24f4e9f82e3ec214450dc3b20a5
WORK_DIR=$(mktemp -d /tmp/fractalos-headscale.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

fetch_checked()
{
    url=$1
    output=$2
    expected=$3
    fetch -o "$output" "$url"
    actual=$(sha256 -q "$output")
    [ "$actual" = "$expected" ] || {
        echo "headscale checksum mismatch: expected $expected got $actual" >&2
        exit 1
    }
}

install -d -m 0755 /usr/local/etc/headscale
install -d -o root -g wheel -m 0700 /var/db/fractalos-secrets/headscale
install -d -o root -g wheel -m 0750 /var/db/headscale
pw usershow headscale >/dev/null 2>&1 || \
    pw useradd headscale -d /var/db/headscale -s /usr/sbin/nologin -c "FractalOS Headscale"

export ASSUME_ALWAYS_YES=yes
pkg bootstrap -f
arch=$(uname -m)
if [ "$arch" = "amd64" ]; then
    pkg install -y ca_root_nss openssl python311 sqlite3
    binary="$WORK_DIR/headscale"
    fetch_checked \
        "https://github.com/juanfont/headscale/releases/download/v${VERSION}/headscale_${VERSION}_freebsd_amd64" \
        "$binary" "$AMD64_SHA"
    install -o root -g wheel -m 0755 "$binary" /usr/local/sbin/headscale
else
    pkg install -y ca_root_nss go git-lite openssl python311 sqlite3
    source="$WORK_DIR/headscale.tar.gz"
    fetch_checked \
        "https://github.com/juanfont/headscale/releases/download/v${VERSION}/headscale_${VERSION}.tar.gz" \
        "$source" "$SOURCE_SHA"
    mkdir "$WORK_DIR/source"
    tar -xzf "$source" -C "$WORK_DIR/source"
    (cd "$WORK_DIR/source" && \
        CGO_ENABLED=1 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=v${VERSION}" \
        -o "$WORK_DIR/headscale" ./cmd/headscale)
    install -o root -g wheel -m 0755 "$WORK_DIR/headscale" /usr/local/sbin/headscale
fi

# The versioned FreeBSD port does not guarantee the unversioned executable
# expected by portable `#!/usr/bin/env python3` tools.
if [ ! -x /usr/local/bin/python3 ]; then
    ln -s /usr/local/bin/python3.11 /usr/local/bin/python3
fi

install -o root -g headscale -m 0640 "$ROLE_DIR/files/config.yaml" /usr/local/etc/headscale/config.yaml
install -o root -g headscale -m 0640 "$ROLE_DIR/files/policy.hujson" /usr/local/etc/headscale/policy.hujson
install -o root -g headscale -m 0640 "$ROLE_DIR/files/netcap-map.json" /usr/local/etc/headscale/netcap-map.json
install -o root -g wheel -m 0555 "$ROLE_DIR/files/headscale.rc" /usr/local/etc/rc.d/headscale
# rc(8) and cron(8) intentionally use a minimal PATH that excludes
# /usr/local/bin, so install a FreeBSD-specific absolute interpreter line.
sed '1s|^.*$|#!/usr/local/bin/python3.11|' "$ROLE_DIR/files/policy-sync.py" \
    > "$WORK_DIR/policy-sync.py"
install -o root -g wheel -m 0555 "$WORK_DIR/policy-sync.py" /usr/local/sbin/fractalos-headscale-policy-sync
printf '%s\n' '*/1 * * * * root /usr/local/sbin/fractalos-headscale-policy-sync >/dev/null 2>&1' \
    > /etc/cron.d/fractalos-headscale-policy-sync
chmod 0600 /etc/cron.d/fractalos-headscale-policy-sync

if [ ! -s /var/db/fractalos-secrets/headscale/tls.key ]; then
    openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
        -subj "/CN=mesh.fractalos.internal" \
        -addext "subjectAltName = DNS:mesh.fractalos.internal" \
        -keyout /var/db/fractalos-secrets/headscale/tls.key \
        -out /var/db/fractalos-secrets/headscale/tls.crt
fi
chown -R headscale:headscale /var/db/headscale /var/db/fractalos-secrets/headscale
chmod 0700 /var/db/fractalos-secrets/headscale
chmod 0600 /var/db/fractalos-secrets/headscale/*

/usr/local/sbin/headscale configtest -c /usr/local/etc/headscale/config.yaml
chown -R headscale:headscale /var/db/headscale /var/db/fractalos-secrets/headscale
chmod 0600 /var/db/fractalos-secrets/headscale/*
sysrc headscale_enable=YES >/dev/null
# Reinstalling the role is supported, so replace an existing controller cleanly.
service headscale onestop >/dev/null 2>&1 || true
service headscale onestart
headscale_ready=0
wait_count=0
while [ "$wait_count" -lt 30 ]; do
    if [ -S /var/run/headscale/headscale.sock ] && \
        /usr/local/sbin/headscale -c /usr/local/etc/headscale/config.yaml \
            nodes list --output json >/dev/null 2>&1; then
        headscale_ready=1
        break
    fi
    wait_count=$((wait_count + 1))
    sleep 1
done
[ "$headscale_ready" -eq 1 ] || {
    echo "headscale management socket did not become ready" >&2
    exit 1
}
/usr/local/sbin/headscale -c /usr/local/etc/headscale/config.yaml users create agent-admin >/dev/null 2>&1 || true
/usr/local/sbin/headscale -c /usr/local/etc/headscale/config.yaml users create agents >/dev/null 2>&1 || true
if [ ! -s /var/db/fractalos-secrets/headscale/api.token ]; then
    /usr/local/sbin/headscale -c /usr/local/etc/headscale/config.yaml \
        apikeys create --expiration 365d \
        > /var/db/fractalos-secrets/headscale/api.token
    chown headscale:headscale /var/db/fractalos-secrets/headscale/api.token
    chmod 0600 /var/db/fractalos-secrets/headscale/api.token
fi
/usr/local/sbin/fractalos-headscale-policy-sync
echo "FractalOS mesh-controller ${VERSION} installed"
