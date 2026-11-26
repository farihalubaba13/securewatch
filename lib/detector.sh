#!/usr/bin/env bash

# detector.sh - Finds brute-force attacks, successful logins after
# repeated failures, and all suspicious IP addresses.

# Feature 4: Detecting brute-force attacks

# Shows one line for each IP with failed attempts equal to or above
# FAIL_THRESHOLD:
#   count<TAB>ip<TAB>first attempt<TAB>last attempt
# Shows the IP with the most failed attempts first.
get_bruteforce_ips() {
    awk -F'\t' -v limit="$FAIL_THRESHOLD" '
        $1 == "FAILED" && $5 != "-" {
            count[$5]++
            if (!($5 in first)) first[$5] = $2 " " $3
            last[$5] = $2 " " $3
        }
        END {
            for (ip in count)
                if (count[ip] >= limit)
                    printf "%d\t%s\t%s\t%s\n", count[ip], ip, first[ip], last[ip]
        }' "$EVENTS_FILE" | sort -t $'\t' -k1,1nr -k2,2
}

show_bruteforce() {
    local count ip first last flagged=0

    print_section "Brute-force Attack Detection"
    print_kv "Failure threshold" "$FAIL_THRESHOLD failed attempts from one IP"
    printf '\n'

    while IFS=$'\t' read -r count ip first last; do
        flagged=$(( flagged + 1 ))
        msg_alert "Possible brute-force attack from $ip"
        printf '          %d failed attempts (threshold %d)\n' "$count" "$FAIL_THRESHOLD"
        printf '          First attempt: %s   Last attempt: %s\n\n' "$first" "$last"
    done < <(get_bruteforce_ips)

    if (( flagged == 0 )); then
        msg_success "No IP address reached $FAIL_THRESHOLD failed attempts."
    else
        print_kv "IP addresses flagged" "$flagged"
    fi
}


# Feature 5: Successful login after repeated failures

# Reads events from oldest to newest and counts failed attempts
# separately for each IP address.
# When a successful login comes from an IP whose failure count
# reaches FAIL_THRESHOLD, prints:
#   date<TAB>time<TAB>user<TAB>ip<TAB>failures before the login
# After a successful login, resets that IP's failure count to zero.
get_success_after_failure() {
    local type date time user ip
    local -A failures=()

    while IFS=$'\t' read -r type date time user ip _; do
        if [[ $ip == "-" ]]; then
            continue
        fi

        if [[ $type == "FAILED" ]]; then
            failures[$ip]=$(( ${failures[$ip]:-0} + 1 ))
        elif [[ $type == "ACCEPTED" ]]; then
            if (( ${failures[$ip]:-0} >= FAIL_THRESHOLD )); then
                printf '%s\t%s\t%s\t%s\t%s\n' "$date" "$time" "$user" "$ip" "${failures[$ip]}"
            fi
            failures[$ip]=0
        fi
    done < "$EVENTS_FILE"
}

show_success_after_failure() {
    local date time user ip failures found=0

    print_section "Successful Login After Repeated Failures"
    print_kv "Failure threshold" "$FAIL_THRESHOLD failed attempts before a login"
    printf '\n'

    while IFS=$'\t' read -r date time user ip failures; do
        found=$(( found + 1 ))
        msg_critical "$user logged in from $ip after $failures failed attempts"
        printf '             Login time: %s %s\n' "$date" "$time"
        printf '             The password may have been guessed. Check this account now.\n\n'
    done < <(get_success_after_failure)

    if (( found == 0 )); then
        msg_success "No successful login followed $FAIL_THRESHOLD or more failed attempts."
    else
        print_kv "Critical alerts" "$found"
    fi
}


# Summary of suspicious IP addresses (used in the security report)

# An IP is suspicious if it matches at least one rule:
# brute-force attack, successful login after repeated failures,
# or failed login attempts with invalid usernames.
show_suspicious_ips() {
    local count ip
    local -A failed=() reasons=()

    while read -r count ip; do
        failed[$ip]=$count
    done < <(get_failed_counts 5)

    while IFS=$'\t' read -r count ip _; do
        reasons[$ip]+="brute force, "
    done < <(get_bruteforce_ips)

    while read -r ip; do
        reasons[$ip]+="login after failures, "
    done < <(get_success_after_failure | cut -f4 | sort -u)

    while read -r ip; do
        reasons[$ip]+="invalid usernames, "
    done < <(get_invalid_attempts | cut -f5 | grep -v '^-$' | sort -u)

    print_section "Suspicious IP Addresses"
    if (( ${#reasons[@]} == 0 )); then
        msg_success "No suspicious IP addresses were found."
        return 0
    fi

    printf '  %-18s %9s   %s\n' "IP Address" "Failures" "Reason"
    printf '  %-18s %9s   %s\n' "------------------" "---------" "------------------------------"
    for ip in "${!reasons[@]}"; do
        printf '%s\t%s\n' "${failed[$ip]:-0}" "$ip"
    done | sort -t $'\t' -k1,1nr -k2,2 | while IFS=$'\t' read -r count ip; do
        printf '  %-18s %9s   %s\n' "$ip" "$count" "${reasons[$ip]%, }"
    done
    printf '\n'
    print_kv "Suspicious IP addresses" "${#reasons[@]}"
}


# Full summary (used in the report and with the -r option)
show_overall_summary() {
    local accepted failed invalid brute critical root odd sudo_cmd sudo_fail
    local level color reason

    accepted=$(count_events ACCEPTED)
    failed=$(count_events FAILED)
    invalid=$(get_invalid_attempts | wc -l)
    brute=$(get_bruteforce_ips | wc -l)
    critical=$(get_success_after_failure | wc -l)
    root=$(get_root_logins | wc -l)
    odd=$(get_odd_hour_logins | wc -l)
    sudo_cmd=$(count_events SUDO_CMD)
    sudo_fail=$(count_events SUDO_FAIL)

    if (( critical > 0 )); then
        level="HIGH"
        color="$C_RED"
        reason="An account was accessed after repeated failed attempts."
    elif (( brute > 0 )); then
        level="MEDIUM"
        color="$C_YELLOW"
        reason="Brute-force activity was found, but no attack succeeded."
    else
        level="LOW"
        color="$C_GREEN"
        reason="No attack pattern reached the configured thresholds."
    fi

    print_section "Overall Summary"
    print_kv "Successful logins" "$accepted"
    print_kv "Failed login attempts" "$failed"
    print_kv "Invalid user attempts" "$invalid"
    print_kv "Brute-force sources" "$brute"
    print_kv "Logins after repeated failures" "$critical"
    print_kv "Successful root logins" "$root"
    print_kv "Odd-hour logins" "$odd"
    print_kv "Sudo commands" "$sudo_cmd"
    print_kv "Failed sudo attempts" "$sudo_fail"
    printf '\n'
    printf '  %-31s: %s%s%s\n' "Overall risk level" "$C_BOLD$color" "$level" "$C_RESET"
    print_kv "Reason" "$reason"
}
