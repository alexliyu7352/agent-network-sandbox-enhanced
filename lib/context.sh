#!/bin/bash
# Workload context is data, never the environment of privileged helpers.
context_kind() {
    case ${1:-} in
        LANG|LANGUAGE|LC_ALL|LC_CTYPE|LC_NUMERIC|LC_TIME|LC_COLLATE|LC_MONETARY|\
        LC_MESSAGES|LC_PAPER|LC_NAME|LC_ADDRESS|LC_TELEPHONE|LC_MEASUREMENT|LC_IDENTIFICATION|TZ)
            printf '%s\n' locale ;;
        DISPLAY|XAUTHORITY|WAYLAND_DISPLAY|XDG_RUNTIME_DIR|DBUS_SESSION_BUS_ADDRESS|\
        XDG_SESSION_TYPE|XDG_CURRENT_DESKTOP)
            printf '%s\n' desktop ;;
        *) return 1 ;;
    esac
}

read_context() {
    [[ $# -ge 2 && $1 =~ ^0?[0-7]{3}$ && $2 =~ ^[0-9]{1,2}$ ]] || return 1
    local count=$((10#$2)) item
    (( count <= 64 && $# >= count + 2 )) || return 1
    CONTEXT_UMASK=$1
    CONTEXT_SHIFT=$((count + 2))
    CONTEXT_ENV=("${@:3:count}")
    for item in "${CONTEXT_ENV[@]}"; do
        [[ $item == *=* ]] || return 1
        context_kind "${item%%=*}" >/dev/null || return 1
    done
}

restore_workload_context() {
    # This helper runs as the target user, after all admission checks. Keep
    # unset and empty distinct; in particular, do not force LC_ALL or LANG.
    read_context "$@" || { echo 'Invalid workload context' >&2; return 125; }
    shift "$CONTEXT_SHIFT"
    (( $# )) || { echo 'Missing workload command' >&2; return 125; }
    local name item
    for name in ${!LC_@} LANG LANGUAGE TZ DISPLAY XAUTHORITY WAYLAND_DISPLAY \
        XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS XDG_SESSION_TYPE XDG_CURRENT_DESKTOP; do
        unset "$name"
    done
    for item in "${CONTEXT_ENV[@]}"; do
        export "$item"
    done
    umask "$CONTEXT_UMASK"
    exec -- "$@"
}

wrap_workload_context() {
    [[ $# -ge 3 ]] || return 1
    local target_uid=$1 caller_uid=$2 mask=$3 item kind helper
    local selected=()
    shift 3
    [[ $target_uid =~ ^[1-9][0-9]*$ ]] || return 1
    read_context "$mask" "$#" "$@" || return 1
    for item in "${CONTEXT_ENV[@]}"; do
        kind=$(context_kind "${item%%=*}") || return 1
        # Never hand a different account the caller's desktop credentials or
        # session bus. The desktop's own authentication remains in force.
        if [[ $kind == locale || $target_uid == "$caller_uid" ]]; then
            selected+=("$item")
        fi
    done
    (( ${#workload[@]} )) || return 1
    helper=$(declare -f context_kind read_context restore_workload_context)
    helper+=$'\nset -euo pipefail\nrestore_workload_context "$@"'
    workload=(/bin/bash -p -c "$helper" session-context "$mask" "${#selected[@]}"
        "${selected[@]}" "${workload[@]}")
}
