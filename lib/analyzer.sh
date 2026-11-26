#!/usr/bin/env bash

# Shows log details, failed logins, invalid users, root logins,
# odd-hour logins and sudo activity.

# get_* functions return raw data.
# show_* functions display formatted results.

# Data helper functions

# Counts events of a specific type. Example: count_events FAILED
count_events() {
    grep -c "^$1"$'\t' "$EVENTS_FILE"
}

# Counts failed attempts by username (4) or IP address (5).
# Shows the highest counts first.
get_failed_counts() {
    local field="$1"

    awk -F'\t' -v f="$field" '$1 == "FAILED" && $f != "-" { print $f }' "$EVENTS_FILE" \
        | sort | uniq -c | sort -k1,1nr -k2,2
}

# Shows failed login attempts with unknown usernames.
get_invalid_attempts() {
    awk -F'\t' '$1 == "FAILED" && $6 == "invalid"' "$EVENTS_FILE"
}

# Prints successful logins to the root account.
get_root_logins() {
    awk -F'\t' '$1 == "ACCEPTED" && $4 == "root"' "$EVENTS_FILE"
}

# Checks if a time (e.g. "03:14:22") is within the
# odd-hour range set by ODD_HOUR_START and ODD_HOUR_END.
is_odd_hour() {
    local time="$1"
    local hour

    [[ $time =~ ^[0-9]{2}: ]] || return 1

    # 10# makes Bash read "08" and "09" as decimal numbers, not octal.
    hour=$(( 10#${time:0:2} ))

    if (( ODD_HOUR_START < ODD_HOUR_END )); then
        (( hour >= ODD_HOUR_START && hour < ODD_HOUR_END ))
    else
        # Window that crosses midnight, for example 22 to 6
        (( hour >= ODD_HOUR_START || hour < ODD_HOUR_END ))
    fi
}

# Prints successful logins that happened inside the odd-hour window.
get_odd_hour_logins() {
    local type date time user ip detail command

    while IFS=$'\t' read -r type date time user ip detail command; do
        if [[ $type == "ACCEPTED" ]] && is_odd_hour "$time"; then
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$type" "$date" "$time" "$user" "$ip" "$detail" "$command"
        fi
    done < "$EVENTS_FILE"
}

# Prints a ranked table from "count value" lines read on standard input.
# Usage: get_failed_counts 5 | print_ranked_table "IP Address" "Attempts"
print_ranked_table() {
    local label="$1" count_label="$2"
    local rank=0 count value

    printf '  %-6s %-26s %10s\n' "Rank" "$label" "$count_label"
    printf '  %-6s %-26s %10s\n' "----" "--------------------------" "----------"
    while read -r count value; do
        rank=$(( rank + 1 ))
        if (( rank > TOP_LIMIT )); then
            break
        fi
        printf '  %-6s %-26s %10s\n' "$rank" "$value" "$count"
    done
}

# Prints the full name of the Linux distribution, e.g. "Ubuntu 24.04.1 LTS".
get_distro_name() {
    if [[ -r /etc/os-release ]]; then
        # The subshell ( ) keeps the variables from os-release out of SecureWatch.
        # shellcheck source=/dev/null
        ( . /etc/os-release && printf '%s\n' "${PRETTY_NAME:-$NAME}" )
    else
        printf 'Unknown\n'
    fi
}


# Feature 1: Log validation and information


show_log_info() {
    local first last path found=0

    print_section "Log Validation and Information"
    msg_success "The log file exists, is readable and is not empty."

    print_subheading "Log file"
    print_kv "Path" "$(short_path "$LOG_FILE")"
    print_kv "Size" "$(wc -c < "$LOG_FILE") bytes"
    print_kv "Last modified" "$(date -r "$LOG_FILE" '+%Y-%m-%d %H:%M:%S')"
    print_kv "Total lines" "$TOTAL_LINES"
    print_kv "Login-related records" "$TOTAL_RECORDS"
    print_kv "Ignored lines" "$(( TOTAL_LINES - TOTAL_RECORDS ))"

    if (( TOTAL_RECORDS > 0 )); then
        # sed prints the first ('1p') and last ('$p') record of the event table.
        first=$(sed -n '1p' "$EVENTS_FILE" | cut -f2,3 | tr '\t' ' ')
        last=$(sed -n '$p' "$EVENTS_FILE" | cut -f2,3 | tr '\t' ' ')
        print_kv "First record" "$first"
        print_kv "Last record" "$last"
    fi

    print_subheading "Record types"
    print_kv "Successful logins" "$(count_events ACCEPTED)"
    print_kv "Failed login attempts" "$(count_events FAILED)"
    print_kv "Sudo commands" "$(count_events SUDO_CMD)"
    print_kv "Failed sudo attempts" "$(count_events SUDO_FAIL)"

    print_subheading "This computer"
    print_kv "Linux distribution" "$(get_distro_name)"
    for path in /var/log/auth.log /var/log/secure; do
        if [[ -e $path ]]; then
            found=1
            if [[ -r $path ]]; then
                print_kv "$path" "found, readable"
            else
                print_kv "$path" "found, needs sudo to read"
            fi
        fi
    done
    if (( found == 0 )); then
        msg_info "No /var/log/auth.log or /var/log/secure was found on this computer."
        msg_info "Login records are probably kept in the systemd journal (see README)."
    fi
}


# Feature 2: Failed login analysis


show_failed_summary() {
    local total invalid unique_ips top_count top_ip

    total=$(count_events FAILED)
    invalid=$(get_invalid_attempts | wc -l)
    unique_ips=$(get_failed_counts 5 | wc -l)

    print_section "Failed Login Analysis"
    if (( total == 0 )); then
        msg_success "No failed login attempts were found."
        return 0
    fi

    print_kv "Total failed attempts" "$total"
    print_kv "Attempts on existing accounts" "$(( total - invalid ))"
    print_kv "Attempts on invalid accounts" "$invalid"
    print_kv "Unique source IP addresses" "$unique_ips"

    print_subheading "Top source IP addresses"
    get_failed_counts 5 | print_ranked_table "IP Address" "Attempts"

    print_subheading "Most targeted usernames"
    get_failed_counts 4 | print_ranked_table "Username" "Attempts"

    read -r top_count top_ip < <(get_failed_counts 5)
    if [[ -n $top_ip ]]; then
        printf '\n'
        msg_warn "Most active source: $top_ip with $top_count failed attempts."
    fi
}


# Feature 3: Invalid user detection


show_invalid_users() {
    local count type date time user ip

    count=$(get_invalid_attempts | wc -l)

    print_section "Invalid User Detection"
    if (( count == 0 )); then
        msg_success "No login attempts with invalid usernames were found."
        return 0
    fi

    msg_warn "$count failed attempts used usernames that do not exist on the server."

    print_subheading "Attempts"
    printf '  %-11s %-10s %-16s %s\n' "Date" "Time" "Username" "Source IP"
    printf '  %-11s %-10s %-16s %s\n' "-----------" "--------" "----------------" "---------------"
    while IFS=$'\t' read -r type date time user ip _; do
        printf '  %-11s %-10s %-16s %s\n' "$date" "$time" "$user" "$ip"
    done < <(get_invalid_attempts)

    print_subheading "Usernames tried"
    get_invalid_attempts | cut -f4 | sort | uniq -c | sort -k1,1nr -k2,2 \
        | print_ranked_table "Username" "Attempts"
}


# Feature 6: Root login monitoring


show_root_logins() {
    local count failed_root type date time user ip method

    count=$(get_root_logins | wc -l)
    failed_root=$(awk -F'\t' '$1 == "FAILED" && $4 == "root"' "$EVENTS_FILE" | wc -l)

    print_section "Root Login Monitoring"
    if (( count == 0 )); then
        msg_success "No successful root logins were found."
    else
        msg_alert "$count successful root login(s) found. Direct root access should be rare."
        printf '\n'
        printf '  %-11s %-10s %-8s %-16s %s\n' "Date" "Time" "User" "Source IP" "Method"
        printf '  %-11s %-10s %-8s %-16s %s\n' "-----------" "--------" "--------" "----------------" "---------"
        while IFS=$'\t' read -r type date time user ip method _; do
            printf '  %-11s %-10s %-8s %-16s %s\n' "$date" "$time" "$user" "$ip" "$method"
        done < <(get_root_logins)
    fi

    printf '\n'
    print_kv "Successful root logins" "$count"
    print_kv "Failed root login attempts" "$failed_root (not counted as logins)"
}


# Feature 7: Odd-hour login detection


show_odd_hour_logins() {
    local window count record type date time user ip method
    local -a records=()

    printf -v window '%02d:00 - %02d:00' "$ODD_HOUR_START" "$ODD_HOUR_END"
    mapfile -t records < <(get_odd_hour_logins)
    count=${#records[@]}

    print_section "Odd-Hour Login Detection"
    print_kv "Odd-hour window" "$window"
    printf '\n'

    if (( count == 0 )); then
        msg_success "No successful logins were found inside the odd-hour window."
        return 0
    fi

    msg_warn "$count successful login(s) happened inside the odd-hour window."
    printf '\n'
    printf '  %-11s %-10s %-10s %-16s %s\n' "Date" "Time" "User" "Source IP" "Method"
    printf '  %-11s %-10s %-10s %-16s %s\n' "-----------" "--------" "----------" "----------------" "---------"
    for record in "${records[@]}"; do
        IFS=$'\t' read -r type date time user ip method _ <<< "$record"
        printf '  %-11s %-10s %-10s %-16s %s\n' "$date" "$time" "$user" "$ip" "$method"
    done

    printf '\n'
    msg_info "Odd-hour logins are not always attacks. Confirm them with the account owners."
}


# Feature 8: Sudo activity monitoring


show_sudo_activity() {
    local cmd_count fail_count type date time user ip reason command

    cmd_count=$(count_events SUDO_CMD)
    fail_count=$(count_events SUDO_FAIL)

    print_section "Sudo Activity Monitoring"
    print_kv "Commands run with sudo" "$cmd_count"
    print_kv "Failed sudo attempts" "$fail_count"

    if (( cmd_count > 0 )); then
        print_subheading "Commands run with sudo"
        printf '  %-11s %-10s %-8s %s\n' "Date" "Time" "User" "Command"
        printf '  %-11s %-10s %-8s %s\n' "-----------" "--------" "--------" "------------------------------"
        while IFS=$'\t' read -r type date time user ip reason command; do
            printf '  %-11s %-10s %-8s %s\n' "$date" "$time" "$user" "$command"
        done < <(grep "^SUDO_CMD"$'\t' "$EVENTS_FILE")

        print_subheading "Sudo commands by user"
        grep "^SUDO_CMD"$'\t' "$EVENTS_FILE" | cut -f4 | sort | uniq -c | sort -k1,1nr -k2,2 \
            | print_ranked_table "User" "Commands"
    fi

    if (( fail_count > 0 )); then
        print_subheading "Failed sudo attempts"
        printf '  %-11s %-10s %-8s %s\n' "Date" "Time" "User" "Reason"
        printf '  %-11s %-10s %-8s %s\n' "-----------" "--------" "--------" "------------------------------"
        while IFS=$'\t' read -r type date time user ip reason command; do
            if [[ $command != "-" ]]; then
                reason="$reason ($command)"
            fi
            printf '  %-11s %-10s %-8s %s\n' "$date" "$time" "$user" "$reason"
        done < <(grep "^SUDO_FAIL"$'\t' "$EVENTS_FILE")
        printf '\n'
        msg_warn "Failed sudo attempts can mean a mistyped password or an attempt to gain root access."
    fi

    if (( cmd_count == 0 && fail_count == 0 )); then
        msg_success "No sudo activity was found in this log."
    fi
}
