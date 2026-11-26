#!/usr/bin/env bash

# parser.sh - Reads login logs and creates simple event records.
# Other files use these records to analyze login activities.

# Each event is stored in one line with TAB-separated fields.
#   1 type     FAILED, ACCEPTED, SUDO_CMD or SUDO_FAIL
#   2 date     "Nov 20" or "2026-11-20"
#   3 time     HH:MM:SS
#   4 user     username
#   5 ip       IP address of the remote computer
#   6 detail   extra information about the event
#   7 command  command run with sudo
# Empty fields are marked with "-".

# Event variables used by other files.
# shellcheck disable=SC2034

# Stores search patterns for reading log entries.
RE_ISO_STAMP='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
RE_FAILED='^Failed password for (invalid user )?([^ ]+) from'
RE_ACCEPTED='^Accepted ([^ ]+) for ([^ ]+) from'
RE_IPV4='from ([0-9]{1,3}(\.[0-9]{1,3}){3})'
RE_SUDO_USER='^([^ ]+) : '
RE_SUDO_RUSER='ruser=([^ ]+)'
RE_SUDO_COMMAND='COMMAND=(.*)$'

# Reads a log line and saves its information in event variables.
# Returns 0 if the line contains a login event, otherwise 1.
parse_line() {
    local line="$1"
    local stamp month day proc msg

    EV_TYPE=""
    EV_DATE="-"
    EV_TIME="-"
    EV_USER="-"
    EV_IP="-"
    EV_DETAIL="-"
    EV_COMMAND="-"

    # The first word tells us which timestamp format the line uses.
    stamp="${line%% *}"
    if [[ $stamp =~ $RE_ISO_STAMP ]]; then
        # 2026-11-20T03:14:22.512094+06:00 srv01 sshd[1250]: message
        read -r stamp _ proc msg <<< "$line"
        EV_DATE="${stamp%%T*}"
        EV_TIME="${stamp#*T}"
        EV_TIME="${EV_TIME:0:8}"
    else
        # A log entry with date, time and message.
        read -r month day EV_TIME _ proc msg <<< "$line"
        EV_DATE="$month $day"
    fi

    # Removes the process ID from the service name.
    proc="${proc%%\[*}"
    proc="${proc%:}"

    if [[ $proc == sshd* ]]; then
        parse_ssh_message "$msg" || return 1
    elif [[ $proc == "sudo" ]]; then
        parse_sudo_message "$msg" || return 1
    else
        return 1
    fi
    return 0
}

# Reads SSH login messages.
parse_ssh_message() {
    local msg="$1"

    if [[ $msg =~ $RE_FAILED ]]; then
        EV_TYPE="FAILED"
        EV_USER="${BASH_REMATCH[2]}"
        if [[ -n ${BASH_REMATCH[1]} ]]; then
            EV_DETAIL="invalid"
        fi
    elif [[ $msg =~ $RE_ACCEPTED ]]; then
        EV_TYPE="ACCEPTED"
        EV_DETAIL="${BASH_REMATCH[1]}"
        EV_USER="${BASH_REMATCH[2]}"
    else
        return 1
    fi

    # Uses "-" if no IP address is found.
    if [[ $msg =~ $RE_IPV4 ]]; then
        EV_IP="${BASH_REMATCH[1]}"
    fi
    return 0
}

# Reads sudo messages. Checks failed attempts before commands.
parse_sudo_message() {
    local msg="$1"

    if [[ $msg == *"authentication failure"* ]]; then
        EV_TYPE="SUDO_FAIL"
        EV_DETAIL="authentication failure"
    elif [[ $msg == *"incorrect password attempt"* ]]; then
        EV_TYPE="SUDO_FAIL"
        EV_DETAIL="incorrect password"
    elif [[ $msg == *"NOT in sudoers"* ]]; then
        EV_TYPE="SUDO_FAIL"
        EV_DETAIL="not in sudoers"
    elif [[ $msg == *"COMMAND="* ]]; then
        EV_TYPE="SUDO_CMD"
    else
        return 1
    fi

    # Some lines show the username at the start.
    # Other lines show it as "ruser=username".
    if [[ $msg =~ $RE_SUDO_USER ]]; then
        EV_USER="${BASH_REMATCH[1]}"
    elif [[ $msg =~ $RE_SUDO_RUSER ]]; then
        EV_USER="${BASH_REMATCH[1]}"
    fi

    if [[ $msg =~ $RE_SUDO_COMMAND ]]; then
        EV_COMMAND="${BASH_REMATCH[1]}"
        EV_COMMAND="${EV_COMMAND//$'\t'/ }"
    fi
    return 0
}

# Saves event information in one line, separated by tabs.
print_event_record() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$EV_TYPE" "$EV_DATE" "$EV_TIME" "$EV_USER" "$EV_IP" "$EV_DETAIL" "$EV_COMMAND"
}

# Checks the log file and saves its events in EVENTS_FILE.
# On success, updates the log file and record counts.
# If loading fails, keeps the previous log file active.
load_log() {
    local file="$1"
    local line

    validate_log_file "$file" || return 1

    TOTAL_LINES=0
    TOTAL_RECORDS=0
    while IFS= read -r line || [[ -n $line ]]; do
        line="${line%$'\r'}"
        TOTAL_LINES=$(( TOTAL_LINES + 1 ))
        if parse_line "$line"; then
            print_event_record
            TOTAL_RECORDS=$(( TOTAL_RECORDS + 1 ))
        fi
    done < "$file" > "$EVENTS_FILE"

    LOG_FILE="$file"
    LOG_LOADED=1

    if (( TOTAL_RECORDS == 0 )); then
        msg_warn "No login-related records were found in $(short_path "$file")."
    fi
    return 0
}
