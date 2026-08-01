#!/usr/bin/env sh
set -eu

root=${1:-/host}
bootstrap="$root/home/codexops/family-proxy-bootstrap"
stamp=$(date +%Y%m%d-%H%M%S)
backup="$root/var/backups/family-proxy/access-$stamp"

mkdir -p "$backup"
chmod 700 "$backup"
cp -a "$root/etc/sudoers" "$backup/sudoers"
if [ -e "$root/etc/sudoers.d/codexops-family-proxy" ]; then
    cp -a "$root/etc/sudoers.d/codexops-family-proxy" "$backup/"
fi

install -o root -g root -m 750 "$bootstrap/deploy-family-proxy-ui" "$root/usr/local/sbin/deploy-family-proxy-ui"
install -o root -g root -m 440 "$bootstrap/codexops-family-proxy.sudoers" "$root/etc/sudoers.d/codexops-family-proxy"
chroot "$root" /usr/sbin/visudo -cf /etc/sudoers.d/codexops-family-proxy
echo "access-backup=$backup"
