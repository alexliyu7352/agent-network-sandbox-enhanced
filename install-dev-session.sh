#!/bin/bash -p
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset BASH_ENV ENV CDPATH GLOBIGNORE
umask 077
[[ $EUID -eq 0 ]] || { echo 'Installer requires root' >&2; exit 125; }
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ $source_dir =~ ^/[A-Za-z0-9_/-]+$ && $source_dir != / ]] || {
    echo 'Use an installation path containing only letters, digits, /, _ and -' >&2; exit 125;
}
# Validate the source helper without sourcing user-writable ancestors.
p=$source_dir/lib/host.sh
while :; do
    [[ -e $p && ! -L $p ]] || exit 125
    read -r owner mode < <(stat -c '%u %a' "$p")
    [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 )) || exit 125
    [[ $p == / ]] && break
    p=${p%/*}; p=${p:-/}
done
source "$source_dir/lib/host.sh"
check=no link=yes
for arg in "$@"; do
    case $arg in
        --check) check=yes ;;
        --no-link) link=no ;;
        *) die 'Usage: install-dev-session.sh [--check] [--no-link]' ;;
    esac
done
for file in dev-session session-launcher install-dev-session.sh lib/main.sh lib/host.sh lib/network.sh lib/cgroup.sh lib/session.sh lib/cli.sh lib/context.sh gateway-policy.jq network.json policy.json \
    Dockerfile.gateway docker-compose.yml entrypoint-gateway.sh .dockerignore; do
    trusted_path "$source_dir/$file" || die "Untrusted source: $file"
    [[ -f $source_dir/$file ]] || die "Not a regular file: $file"
done
# Harden only this checkout. Reject links and foreign/writable files first;
# never chown a user-owned tree into apparent trust or follow it elsewhere.
while IFS= read -r -d '' file; do
    [[ ! -L $file && ( -f $file || -d $file ) ]] || die "Unsupported file: $file"
    read -r owner mode links < <(stat -c '%u %a %h' -- "$file")
    [[ $owner == 0 ]] && (( (8#$mode & 0022) == 0 )) || die "Untrusted checkout file: $file"
    [[ ! -f $file || $links == 1 ]] || die "Hard-linked file refused: $file"
done < <(find "$source_dir" -xdev -print0)
for file in "$source_dir/dev-session" "$source_dir/session-launcher" "$source_dir/install-dev-session.sh" "$source_dir"/lib/*.sh; do
    bash -n "$file"
done
sh -n "$source_dir/entrypoint-gateway.sh"
jq -e '.version==8 and .gateway_container=="worker"' "$source_dir/policy.json" >/dev/null
if [[ -d /run/systemd/system && $(cat /proc/1/comm) == systemd ]]; then
    units=$(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root \
        systemctl list-units --all --plain --no-legend 'dev-session-*.service')
    [[ -z $units ]] || die 'Close all sessions before installing or updating'
fi
shortcut=/usr/local/bin/session
if [[ $link == yes ]]; then
    trusted_path "${shortcut%/*}" || die 'Untrusted public launcher directory'
    if [[ -e $shortcut || -L $shortcut ]]; then
        if [[ -L $shortcut ]]; then
            [[ $(stat -c '%u' -- "$shortcut") == 0 &&
               $(readlink -- "$shortcut") == "$source_dir/dev-session" ]] || die "Shortcut already belongs to another installation: $shortcut"
        else
            trusted_path "$shortcut" && [[ -f $shortcut && $(stat -c '%h' -- "$shortcut") == 1 ]] ||
                die "Untrusted public launcher: $shortcut"
            { IFS= read -r launcher_shebang; IFS= read -r launcher_marker; IFS= read -r launcher_manager; } < "$shortcut" ||
                die "Unrecognized public launcher: $shortcut"
            [[ $launcher_shebang == '#!/bin/bash -p' &&
               $launcher_marker == '# Managed session launcher; format 1.' &&
               $launcher_manager == "manager='$source_dir/dev-session'" ]] ||
                die "Public command already belongs to another installation: $shortcut"
        fi
    fi
    launcher=$(<"$source_dir/session-launcher")
    launcher=${launcher//@SESSION_MANAGER@/$source_dir/dev-session}
    /bin/bash -n <<<"$launcher"
fi
if [[ $check == yes ]]; then
    echo "In-place installation checks passed: $source_dir; nothing changed."
    exit
fi
find "$source_dir" -xdev -type d -exec chown root:root {} + -exec chmod 700 {} +
find "$source_dir" -xdev -type f -exec chown root:root {} + -exec chmod u-s,g-s,o-t,go-rwx {} +
chmod 700 "$source_dir/dev-session" "$source_dir/install-dev-session.sh" "$source_dir/entrypoint-gateway.sh" "$source_dir/lib/main.sh"
chmod 600 "$source_dir/network.json" "$source_dir/policy.json"
if [[ $link == yes ]]; then
    launcher_tmp=$(mktemp "${shortcut%/*}/.session-launcher.XXXXXXXX")
    trap '[[ -z ${launcher_tmp:-} ]] || rm -f -- "$launcher_tmp"' EXIT
    printf '%s\n' "$launcher" > "$launcher_tmp"
    chown root:root "$launcher_tmp"
    chmod 755 "$launcher_tmp"
    mv -fT -- "$launcher_tmp" "$shortcut"
    launcher_tmp=''
fi
echo "Installed in place: $source_dir"
[[ $link == no ]] || echo "Launcher: $shortcut (run session directly; sudo is automatic)"
echo 'No container, firewall, or routing state was changed.'
