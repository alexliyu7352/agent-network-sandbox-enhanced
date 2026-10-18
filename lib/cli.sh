#!/bin/bash
# Parse arguments as data. No shell text or account configuration is sourced.
parse_cli() {
    command='' user='' workdir='' workload=() close_id='' workload_umask=''
    while (( $# )); do
        case $1 in
            -u|--user)
                [[ $# -ge 2 && -z $user ]] || die 'Expected --user ACCOUNT once'
                user=$2; shift 2 ;;
            --cwd)
                [[ $# -ge 2 && -z $workdir ]] || die 'Expected --cwd DIR once'
                workdir=$2
                [[ $workdir == /* ]] || die '--cwd must be an absolute path'
                shift 2 ;;
            --umask)
                [[ $# -ge 2 && -z $workload_umask ]] || die 'Expected --umask OCTAL once'
                [[ $2 =~ ^0?[0-7]{3}$ ]] || die '--umask must be three octal digits, optionally prefixed by 0'
                workload_umask=$2; shift 2 ;;
            run)
                [[ -z $command ]] || die 'Duplicate command'
                command=run; shift ;;
            help|--help|-h|init|check|status|close)
                [[ -z $command && -z $user && -z $workdir && -z $workload_umask ]] || die 'Conflicting command or run options'
                command=$1; shift
                if [[ $command == close ]]; then
                    [[ $# == 1 && $1 =~ ^[0-9a-f]{32}$ ]] || die 'Expected exact 32-digit session ID'
                    close_id=$1; shift
                fi
                [[ $# == 0 ]] || die 'Unexpected argument'
                return 0 ;;
            --)
                shift; workload=("$@"); break ;;
            -*) die "Unknown option: $1" ;;
            *)
                [[ $command == run ]] || die 'Put commands after -- (see session --help)'
                workload=("$@"); break ;;
        esac
    done
    command=${command:-run}
    if [[ -z $workdir ]]; then
        if [[ ${CALLER_WORKDIR+x} ]]; then
            [[ -n $CALLER_WORKDIR ]] || die 'Cannot determine caller working directory; use --cwd DIR'
            workdir=$CALLER_WORKDIR
        else
            workdir=$(pwd -P) || die 'Cannot determine current working directory; use --cwd DIR'
        fi
    fi
}

resolve_account() {
    local account name password gecos login_shell inferred=no
    if [[ -z $user ]]; then
        [[ ${SUDO_UID:-} =~ ^[1-9][0-9]{0,9}$ ]] || die 'Use --user ACCOUNT when running directly as root'
        account=$(getent passwd "$SUDO_UID") || die 'Unknown sudo caller; use --user ACCOUNT'
        user=${account%%:*}; inferred=yes
    else
        [[ $user =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*$ ]] || die 'Invalid --user ACCOUNT'
        account=$(getent passwd "$user") || die 'Unknown account'
    fi
    [[ $account != *$'\n'* ]] || die 'Ambiguous account'
    IFS=: read -r name password uid gid gecos home login_shell <<<"$account"
    [[ $name == "$user" && $uid =~ ^[1-9][0-9]*$ && $gid =~ ^[0-9]+$ && $home == /* ]] || die 'Target must be a non-root account'
    [[ $inferred == no || $uid == "$SUDO_UID" ]] || die 'Sudo caller UID mismatch'
}
