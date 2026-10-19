#!/bin/bash
# Pure definitions. The privileged entrypoint selects or loads one mode under
# its policy lock. A persisted mode is never replaced by fresh autodetection.

cgroup_reset() {
    unset CGROUP_MODE CGROUP_MOUNT CGROUP_MOUNT_IDENTITY CGROUP_MANAGER_HIERARCHY
    unset CGROUP_PATH CGROUP_IDENTITY CGROUP_BOOT_ID CGROOT
}

cgroup_boot_id() { cat /proc/sys/kernel/random/boot_id; }
cgroup_unit_file() { printf '%s\n' /run/systemd/system/devsession.slice; }

cgroup_membership() {
    local pid=${1:-self} line
    [[ $pid == self || $pid =~ ^[1-9][0-9]*$ ]] || return 1
    while IFS= read -r line; do printf '%s\n' "$line"; done <"/proc/$pid/cgroup"
}

cgroup_manager_hierarchy() {
    local mode=$1 data
    data=$(cgroup_membership 1) || return
    if [[ $mode == v1 ]] && awk -F: '
      $2 ~ /(^|,)name=systemd(,|$)/ && $3 ~ /^\// {n++}
      END {exit !(n==1)}' <<<"$data"; then
        printf '%s\n' name=systemd
    elif awk -F: '$1=="0" && $2=="" && $3 ~ /^\// {n++} END {exit !(n==1)}' <<<"$data"; then
        printf '%s\n' 0
    else
        return 1
    fi
}

cgroup_find_mount() {
    local mode=$1 data
    [[ $mode == v1 || $mode == v2 ]] || return 1
    data=$(findmnt --json --list --types cgroup,cgroup2 --output TARGET,FSTYPE,FSROOT,OPTIONS) || return
    jq -r --arg mode "$mode" '
      def safepath: type=="string" and
        test("\\A/(?:[A-Za-z0-9_.,-]+/)*[A-Za-z0-9_.,-]+\\z") and
        (split("/") | all(.[]; .!="." and .!=".."));
      .filesystems | if type!="array" then error("invalid mount inventory") else .[] end |
      select(.fsroot=="/" and (.target|safepath) and (.options|type=="string")) |
      select((.options|split(",")|index("rw"))!=null) |
      select(if $mode=="v1" then .fstype=="cgroup" and
          ((.options|split(",")|index("net_cls"))!=null)
        else .fstype=="cgroup2" end) | .target
    ' <<<"$data"
}

cgroup_probe_v1() (
    local mount=$1 path='' nonce
    [[ ${CLASSID:-} =~ ^0x[0-9a-fA-F]{1,8}$ ]] || return 1
    trusted_path "$mount" || return
    [[ -d $mount && -w $mount && -f $mount/net_cls.classid &&
       -w $mount/net_cls.classid && ! -L $mount/net_cls.classid ]] || return 1
    read -r nonce </proc/sys/kernel/random/uuid || return
    [[ $nonce =~ ^[0-9a-f-]{36}$ ]] || return 1
    path=$mount/.dev-session-probe-${nonce//-/}
    mkdir -- "$path" || return
    trap 'rmdir -- "$path" >/dev/null 2>&1 || :' EXIT
    chmod 700 "$path" || return
    [[ -f $path/net_cls.classid && ! -L $path/net_cls.classid &&
       -w $path/cgroup.procs && ! -L $path/cgroup.procs ]] || return 1
    printf '%s\n' "$((CLASSID))" >"$path/net_cls.classid" || return
    [[ $(cat "$path/net_cls.classid") == "$((CLASSID))" ]] || return 1
    # The permission probe never moves any process, including the caller.
    rmdir -- "$path" || return
    trap - EXIT
)

cgroup_probe_match() (
    local mode=$1 path=${2:-/} family bin chain nonce status=0 created=0
    local -a match
    case $mode in
        v1)
            [[ ${CLASSID:-} =~ ^0x[0-9a-fA-F]{1,8}$ ]] || return 1
            match=(-m cgroup --cgroup "$CLASSID") ;;
        v2)
            [[ $path == / || $path == devsession.slice ]] || return 1
            match=(-m cgroup --path "$path") ;;
        *) return 1 ;;
    esac
    read -r nonce </proc/sys/kernel/random/uuid || return
    [[ $nonce =~ ^[0-9a-f-]{36}$ ]] || return 1
    nonce=${nonce//-/}; chain=D8CGP${nonce:0:16}
    # --help and restore --test alone cannot prove that the running kernel
    # accepts this match revision. Commit one rule in an unreferenced chain;
    # never attach the probe to OUTPUT, POSTROUTING, or another live hook.
    trap 'if (( created )); then
        "$bin" -w 5 -t mangle -F "$chain" >/dev/null 2>&1 || :
        "$bin" -w 5 -t mangle -X "$chain" >/dev/null 2>&1 || :
    fi' EXIT
    for family in 4 6; do
        if [[ $family == 4 ]]; then bin=iptables-legacy; else bin=ip6tables-legacy; fi
        "$bin" -w 5 -t mangle -N "$chain" >/dev/null 2>&1 || return
        created=1
        "$bin" -w 5 -t mangle -A "$chain" "${match[@]}" -j RETURN >/dev/null 2>&1 || status=1
        "$bin" -w 5 -t mangle -F "$chain" >/dev/null 2>&1 || return
        "$bin" -w 5 -t mangle -X "$chain" >/dev/null 2>&1 || return
        created=0
        (( status == 0 )) || return "$status"
    done
    trap - EXIT
)

cgroup_detect() {
    local mode mount candidates hierarchy
    [[ -n ${RUNTIME:-} && ! -e $RUNTIME/binding && ! -L $RUNTIME/binding &&
       -z ${CGROUP_IDENTITY:-} ]] || return 1
    cgroup_reset
    for mode in v1 v2; do
        hierarchy=$(cgroup_manager_hierarchy "$mode") || continue
        candidates=$(cgroup_find_mount "$mode") || continue
        while IFS= read -r mount; do
            [[ -n $mount ]] || continue
            if [[ $mode == v1 ]]; then cgroup_probe_v1 "$mount" || continue; fi
            cgroup_probe_match "$mode" / || continue
            CGROUP_MODE=$mode; CGROUP_MOUNT=$mount
            CGROUP_MANAGER_HIERARCHY=$hierarchy
            if [[ $mode == v1 ]]; then CGROUP_PATH=dev-session-v8; else CGROUP_PATH=devsession.slice; fi
            CGROOT=$CGROUP_MOUNT/$CGROUP_PATH
            return 0
        done <<<"$candidates"
    done
    cgroup_reset
    echo 'No usable cgroup mode: require writable net_cls and systemd membership for v1, or a systemd v2 hierarchy; both IP families must accept the selected legacy cgroup match.' >&2
    return 1
}

cgroup_valid_state() {
    jq -e '
      def safepath: type=="string" and
        test("\\A/(?:[A-Za-z0-9_.,-]+/)*[A-Za-z0-9_.,-]+\\z") and
        (split("/") | all(.[]; .!="." and .!=".."));
      def identity: type=="string" and test("\\A[0-9]+:[1-9][0-9]*\\z");
      type=="object" and
      keys==["boot_id","format","identity","manager_hierarchy","mode","mount","mount_identity","path"] and
      .format==1 and (.mount|safepath) and (.mount_identity|identity) and (.identity|identity) and
      (.boot_id|type=="string" and test("\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z")) and
      (if .mode=="v1" then .path=="dev-session-v8" and
           (.manager_hierarchy=="name=systemd" or .manager_hierarchy=="0")
        elif .mode=="v2" then .path=="devsession.slice" and .manager_hierarchy=="0"
        else false end)
    ' <<<"$1" >/dev/null 2>&1
}

cgroup_load_state() {
    local data mode mount mount_identity hierarchy path identity boot
    cgroup_reset
    cgroup_valid_state "${1:-}" || return 1
    data=$(jq -r '[.mode,.mount,.mount_identity,.manager_hierarchy,.path,.identity,.boot_id]|@tsv' <<<"$1") || return
    IFS=$'\t' read -r mode mount mount_identity hierarchy path identity boot <<<"$data" || return
    CGROUP_MODE=$mode; CGROUP_MOUNT=$mount; CGROUP_MOUNT_IDENTITY=$mount_identity
    CGROUP_MANAGER_HIERARCHY=$hierarchy; CGROUP_PATH=$path
    CGROUP_IDENTITY=$identity; CGROUP_BOOT_ID=$boot
    CGROOT=$CGROUP_MOUNT/$CGROUP_PATH
}

cgroup_state_json() {
    local data
    data=$(jq -cnS --arg mode "${CGROUP_MODE:-}" --arg mount "${CGROUP_MOUNT:-}" \
        --arg mount_identity "${CGROUP_MOUNT_IDENTITY:-}" --arg manager_hierarchy "${CGROUP_MANAGER_HIERARCHY:-}" \
        --arg path "${CGROUP_PATH:-}" --arg identity "${CGROUP_IDENTITY:-}" --arg boot_id "${CGROUP_BOOT_ID:-}" \
        '{format:1,mode:$mode,mount:$mount,mount_identity:$mount_identity,
          manager_hierarchy:$manager_hierarchy,path:$path,identity:$identity,boot_id:$boot_id}') || return
    cgroup_valid_state "$data" || return 1
    printf '%s\n' "$data"
}

cgroup_match() {
    case ${CGROUP_MODE:-} in
        v1)
            [[ ${CLASSID:-} =~ ^0x[0-9a-fA-F]{1,8}$ ]] || return 1
            printf '%s\n' "-m cgroup --cgroup $CLASSID" ;;
        v2) printf '%s\n' '-m cgroup --path devsession.slice' ;;
        *) return 1 ;;
    esac
}

cgroup_slice_text() {
    printf '# dev-session cgroup state format 1\n# Installation: %s\n' "$ROOT"
    printf '%s\n' '[Unit]' 'Description=Dev-session network policy parent' \
        'StopWhenUnneeded=no' 'RefuseManualStop=yes' '' '[Slice]'
}

cgroup_slice_verify() {
    local file data state=${1:-active} group=/devsession.slice
    [[ $state == active || $state == inactive ]] || return 1
    [[ $state != inactive ]] || group=''
    file=$(cgroup_unit_file) || return
    trusted_path "$file" || return
    [[ -f $file && $(cat "$file") == "$(cgroup_slice_text)" ]] || return 1
    data=$(systemctl show --property=LoadState,ActiveState,FragmentPath,DropInPaths,ControlGroup,StopWhenUnneeded,RefuseManualStop -- devsession.slice) || return
    awk -F= -v file="$file" -v state="$state" -v group="$group" '
      NF!=2 || seen[$1]++ {bad=1;next}
      $1=="LoadState" {n++; ok+=($2=="loaded");next}
      $1=="ActiveState" {n++; ok+=($2==state);next}
      $1=="FragmentPath" {n++; ok+=($2==file);next}
      $1=="DropInPaths" {n++; ok+=($2=="");next}
      $1=="ControlGroup" {n++; ok+=($2==group);next}
      $1=="StopWhenUnneeded" {n++; ok+=($2=="no");next}
      $1=="RefuseManualStop" {n++; ok+=($2=="yes");next}
      {bad=1} END {exit !(n==7 && ok==7 && !bad)}' <<<"$data"
}

cgroup_unused() {
    local file data
    [[ -n ${CGROOT:-} && ! -e $CGROOT && ! -L $CGROOT ]] || return 1
    case ${CGROUP_MODE:-} in
        v1) return 0 ;;
        v2)
            file=$(cgroup_unit_file) || return
            [[ ! -e $file && ! -L $file ]] || return 1
            # A synthetic inactive slice with no fragment is safe to create.
            # Existing unit files, drop-ins, active groups or transient owners
            # belong to someone else, even if the name happens to match.
            data=$(systemctl show --property=LoadState,ActiveState,FragmentPath,DropInPaths,ControlGroup,Transient -- devsession.slice) || return
            awk -F= '
              NF!=2 || seen[$1]++ {bad=1;next}
              $1=="LoadState" {n++; ok+=($2=="loaded" || $2=="not-found");next}
              $1=="ActiveState" {n++; ok+=($2=="inactive");next}
              $1=="Transient" {n++; ok+=($2=="no");next}
              $1=="FragmentPath" || $1=="DropInPaths" || $1=="ControlGroup" {n++; ok+=($2=="");next}
              {bad=1} END {exit !(n==6 && ok==6 && !bad)}' <<<"$data" ;;
        *) return 1 ;;
    esac
}

cgroup_prepare() {
    local file
    # Never recreate a bound parent: xt_cgroup holds the original object,
    # and equal path text does not retarget its installed rules or sockets.
    if [[ -n ${CGROUP_IDENTITY:-} ]]; then cgroup_verify; return; fi
    cgroup_unused || return
    [[ -n ${CGROUP_MOUNT:-} && ${CGROOT:-} == "$CGROUP_MOUNT/${CGROUP_PATH:-}" ]] || return 1
    trusted_path "$CGROUP_MOUNT" || return
    case ${CGROUP_MODE:-} in
        v1)
            [[ $CGROUP_PATH == dev-session-v8 ]] || return 1
            mkdir -- "$CGROOT" || return
            chmod 700 "$CGROOT" || return ;;
        v2)
            [[ $CGROUP_PATH == devsession.slice && ${CGROUP_MANAGER_HIERARCHY:-} == 0 ]] || return 1
            file=$(cgroup_unit_file) || return
            trusted_path "${file%/*}" || return
            (set -o noclobber; umask 077; cgroup_slice_text >"$file") || return
            systemctl daemon-reload || return
            # Reload may reveal a higher-precedence administrator unit or a
            # new drop-in. Refuse it before activating anything with this name.
            cgroup_slice_verify inactive || return
            systemctl start devsession.slice || return
            cgroup_slice_verify || return ;;
        *) return 1 ;;
    esac
    CGROUP_MOUNT_IDENTITY=$(stat -c '%d:%i' -- "$CGROUP_MOUNT") || return
    CGROUP_IDENTITY=$(stat -c '%d:%i' -- "$CGROOT") || return
    CGROUP_BOOT_ID=$(cgroup_boot_id) || return
    cgroup_verify
}

cgroup_children_valid() {
    local child name
    for child in "$CGROOT"/* "$CGROOT"/.[!.]* "$CGROOT"/..?*; do
        [[ ! -L $child ]] || return 1
        [[ -d $child ]] || continue
        name=${child##*/}
        case $CGROUP_MODE in
            v1) [[ $name =~ ^[0-9a-f]{32}$ ]] || return 1 ;;
            v2) [[ $name =~ ^dev-session-[0-9a-f]{32}\.service$ ]] || return 1 ;;
            *) return 1 ;;
        esac
    done
}

cgroup_verify() {
    local candidates mount found=0
    cgroup_state_json >/dev/null || return
    [[ $CGROOT == "$CGROUP_MOUNT/$CGROUP_PATH" ]] || return 1
    [[ $(cgroup_boot_id) == "$CGROUP_BOOT_ID" ]] || return 1
    candidates=$(cgroup_find_mount "$CGROUP_MODE") || return
    while IFS= read -r mount; do [[ $mount != "$CGROUP_MOUNT" ]] || found=1; done <<<"$candidates"
    (( found )) || return 1
    [[ $(cgroup_manager_hierarchy "$CGROUP_MODE") == "$CGROUP_MANAGER_HIERARCHY" ]] || return 1
    trusted_path "$CGROUP_MOUNT" && trusted_path "$CGROOT" && trusted_path "$CGROOT/cgroup.procs" || return
    [[ -d $CGROOT && $(stat -c '%d:%i' -- "$CGROUP_MOUNT") == "$CGROUP_MOUNT_IDENTITY" &&
       $(stat -c '%d:%i' -- "$CGROOT") == "$CGROUP_IDENTITY" ]] || return 1
    case $CGROUP_MODE in
        v1) [[ -f $CGROOT/net_cls.classid && ! -L $CGROOT/net_cls.classid && -w $CGROOT ]] || return 1 ;;
        v2)
            [[ -f $CGROOT/cgroup.controllers && -r $CGROOT/cgroup.events &&
               -z $(cat "$CGROOT/cgroup.procs") ]] || return 1
            cgroup_slice_verify || return ;;
        *) return 1 ;;
    esac
    cgroup_children_valid
}

cgroup_sessions_empty() {
    local child
    cgroup_verify || return
    [[ -z $(cat "$CGROOT/cgroup.procs") ]] || return 1
    for child in "$CGROOT"/* "$CGROOT"/.[!.]* "$CGROOT"/..?*; do
        [[ ! -d $child && ! -L $child ]] || return 1
    done
}

cgroup_unit_arguments() {
    CGROUP_UNIT_ARGS=()
    case ${CGROUP_MODE:-} in
        v1) CGROUP_UNIT_ARGS=(--property=Delegate=no) ;;
        v2) CGROUP_UNIT_ARGS=(--slice=devsession.slice --property=Delegate=no) ;;
        *) return 1 ;;
    esac
}

cgroup_self_in_service() {
    local sid=$1 expected data
    [[ $sid =~ ^[0-9a-f]{32}$ ]] || return 1
    case ${CGROUP_MODE:-} in
        v1) expected=/system.slice/dev-session-$sid.service ;;
        v2) expected=/devsession.slice/dev-session-$sid.service ;;
        *) return 1 ;;
    esac
    [[ $(systemctl show --property=ControlGroup --value -- "dev-session-$sid.service") == "$expected" ]] || return 1
    [[ $(systemctl show --property=Delegate --value -- "dev-session-$sid.service") == no ]] || return 1
    data=$(cgroup_membership self) || return
    awk -F: -v hierarchy="$CGROUP_MANAGER_HIERARCHY" -v path="$expected" '
      hierarchy=="0" && $1=="0" && $2=="" && $3==path {n++}
      hierarchy=="name=systemd" && $2 ~ /(^|,)name=systemd(,|$)/ && $3==path {n++}
      END {exit !(n==1)}' <<<"$data"
}

cgroup_attach() {
    local sid=$1 path caller rest data
    [[ $sid =~ ^[0-9a-f]{32}$ ]] || return 1
    cgroup_verify || return
    cgroup_self_in_service "$sid" || return
    if [[ $CGROUP_MODE == v2 ]]; then
        # systemd creates the service in the selected subtree before exec.
        # Moving an already running process would not retag its old sockets.
        trusted_path "$CGROOT/dev-session-$sid.service/cgroup.procs"
        return
    fi
    path=$CGROOT/$sid
    mkdir -- "$path" || return
    chmod 700 "$path" || return
    [[ ! -L $path/net_cls.classid && ! -L $path/cgroup.procs ]] || return 1
    printf '%s\n' "$((CLASSID))" >"$path/net_cls.classid" || return
    [[ $(cat "$path/net_cls.classid") == "$((CLASSID))" ]] || return 1
    read -r caller rest </proc/self/stat || return
    [[ $caller =~ ^[1-9][0-9]*$ ]] || return 1
    printf '%s\n' "$caller" >"$path/cgroup.procs" || return
    data=$(cgroup_membership self) || return
    awk -F: -v path="/$CGROUP_PATH/$sid" '
      $2 ~ /(^|,)net_cls(,|$)/ && $3==path {n++} END {exit !(n==1)}' <<<"$data"
}

cgroup_cleanup() {
    local sid=${1:-} path members populated
    [[ $sid =~ ^[0-9a-f]{32}$ ]] || return 1
    cgroup_verify || return
    case $CGROUP_MODE in
        v1) path=$CGROOT/$sid ;;
        v2) path=$CGROOT/dev-session-$sid.service ;;
        *) return 1 ;;
    esac
    [[ ! -L $path ]] || return 1
    [[ -e $path ]] || return 0
    [[ -d $path && -r $path/cgroup.procs && ! -L $path/cgroup.procs ]] || {
        [[ ! -e $path && ! -L $path ]]; return;
    }
    if [[ $CGROUP_MODE == v2 ]]; then
        [[ -r $path/cgroup.events && ! -L $path/cgroup.events ]] || {
            [[ ! -e $path && ! -L $path ]]; return;
        }
        populated=$(awk '$1=="populated" && ($2==0 || $2==1) && NF==2 {n++; p=$2}
          END {if(n!=1) exit 1; print p}' "$path/cgroup.events") || {
            [[ ! -e $path && ! -L $path ]]; return;
        }
        # ExecStopPost itself can still populate the service; the launcher
        # retries after the stop job. Only systemd removes v2 service groups.
        [[ $populated == 0 ]] || return 2
        return 0
    fi
    members=$(cat "$path/cgroup.procs" 2>/dev/null) || {
        [[ ! -e $path && ! -L $path ]]; return;
    }
    [[ -z $members ]] || return 2
    rmdir -- "$path" 2>/dev/null || [[ ! -e $path && ! -L $path ]]
    # Neither mode ever removes shared rules, routes, or its parent group.
}
