#!/usr/bin/env bash

# Common functions used by all SecureWatch files:
# colors, messages, screen design, input checks and file paths.

# Loaded by securewatch.sh. This file only contains functions.

# Colors used by other files.
# shellcheck disable=SC2034

# Width of lines and titles.
UI_WIDTH=64


# Colors

# Turns off all colors and shows plain text.
disable_colors() {
    C_RESET=""
    C_BOLD=""
    C_DIM=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_CYAN=""
}

# Sets the terminal colors.
# Auto mode uses colors only in the terminal.
setup_colors() {
    local mode="${USE_COLOR:-auto}"

    if [[ $mode == "yes" ]] || [[ $mode == "auto" && -t 1 ]]; then
        C_RESET=$'\033[0m'
        C_BOLD=$'\033[1m'
        C_DIM=$'\033[2m'
        C_RED=$'\033[31m'
        C_GREEN=$'\033[32m'
        C_YELLOW=$'\033[33m'
        C_BLUE=$'\033[34m'
        C_CYAN=$'\033[36m'
    else
        disable_colors
    fi
}


# Messages

msg_info() {
    printf '  %s[INFO]%s %s\n' "$C_BLUE" "$C_RESET" "$*"
}

msg_success() {
    printf '  %s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"
}

msg_warn() {
    printf '  %s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"
}

# Shows errors separately from saved reports.
msg_error() {
    printf '  %s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2
}

msg_alert() {
    printf '  %s[ALERT]%s %s\n' "$C_RED" "$C_RESET" "$*"
}

msg_critical() {
    printf '  %s%s[CRITICAL]%s %s\n' "$C_BOLD" "$C_RED" "$C_RESET" "$*"
}


# Layout

# Prints a line across the screen.
# Usage: print_rule [character] [color]
print_rule() {
    local char="${1:--}" color="${2:-}"
    local rule

    printf -v rule '%*s' "$UI_WIDTH" ''
    printf '%s%s%s\n' "$color" "${rule// /$char}" "$C_RESET"
}

# Prints text in the center.
# Usage: print_center "text" [color]
print_center() {
    local text="$1" color="${2:-}"
    local padding=$(( (UI_WIDTH - ${#text}) / 2 ))

    if (( padding < 0 )); then
        padding=0
    fi
    printf '%*s%s%s%s\n' "$padding" '' "$color" "$text" "$C_RESET"
}

# Application title shown at the top of the menu.
print_banner() {
    print_rule "=" "$C_CYAN"
    print_center "S E C U R E W A T C H" "$C_BOLD$C_CYAN"
    print_center "Linux Authentication Log Analyzer and Security Monitor" "$C_CYAN"
    print_rule "=" "$C_CYAN"
}

# Prints the title of each feature and report section.
print_section() {
    printf '\n'
    print_rule "-" "$C_CYAN"
    printf ' %s%s%s\n' "$C_BOLD" "$1" "$C_RESET"
    print_rule "-" "$C_CYAN"
}

# Prints a small heading with a line below it.
print_subheading() {
    local text="$1"
    local underline

    printf -v underline '%*s' "${#text}" ''
    printf '\n  %s%s%s\n' "$C_BOLD" "$text" "$C_RESET"
    printf '  %s\n' "${underline// /-}"
}

# Prints an aligned "label : value" line.
print_kv() {
    printf '  %-31s: %s\n' "$1" "$2"
}

# Waits for the user before going back to the menu.
pause() {
    printf '\n'
    read -rp "  Press Enter to continue..." _ || true
}

clear_screen() {
    if [[ -t 1 ]] && command -v clear >/dev/null 2>&1; then
        clear
    fi
}


# Validation

# Accepts whole numbers from 1 to 999999 (no signs, no leading zeros).
is_positive_integer() {
    [[ $1 =~ ^[1-9][0-9]{0,5}$ ]]
}

# Accepts an hour from 0 to 23, written with one or two digits.
is_valid_hour() {
    [[ $1 =~ ^(0?[0-9]|1[0-9]|2[0-3])$ ]]
}

# Checks if a log file can be read.
# Usage: validate_log_file <path> [allow_empty]
# Use "yes" to allow an empty file.
# This is needed for real-time monitoring.
validate_log_file() {
    local file="$1" allow_empty="${2:-no}"

    if [[ -z $file ]]; then
        msg_error "No log file was specified."
        return 1
    fi
    if [[ ! -e $file ]]; then
        msg_error "Log file not found: $file"
        return 1
    fi
    if [[ -d $file ]]; then
        msg_error "'$file' is a folder, not a log file."
        return 1
    fi
    if [[ ! -f $file ]]; then
        msg_error "'$file' is not a regular file."
        return 1
    fi
    if [[ ! -r $file ]]; then
        msg_error "Permission denied: you cannot read $file"
        msg_info "System logs are usually readable only by administrators."
        msg_info "Copy the log with sudo and analyze the copy (see README)."
        return 1
    fi
    if [[ $allow_empty != "yes" && ! -s $file ]]; then
        msg_warn "The log file is empty: $file"
        return 1
    fi
    return 0
}

# Checks if the required tools are installed.
check_dependencies() {
    local cmd
    local missing=()

    for cmd in grep awk sed sort uniq cut tail head wc date mktemp; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        msg_error "Missing required commands: ${missing[*]}"
        msg_info "Install them with your package manager and try again."
        return 1
    fi
    return 0
}

# Checks if a command exists, including in /usr/sbin and /sbin.
has_command() {
    command -v "$1" >/dev/null 2>&1 || [[ -x /usr/sbin/$1 || -x /sbin/$1 ]]
}


# Paths

# Config file paths start from the project folder.
resolve_project_path() {
    local path="$1"

    if [[ $path == /* ]]; then
        printf '%s\n' "$path"
    else
        printf '%s\n' "$PROJECT_ROOT/$path"
    fi
}

# Shows shorter paths for project files.
short_path() {
    local path="$1"
    printf '%s\n' "${path#"$PROJECT_ROOT"/}"
}

# Removes extra quotes and expands ~ in a file path.
clean_path_input() {
    local path="$1"

    path="${path#\'}"
    path="${path%\'}"
    path="${path#\"}"
    path="${path%\"}"
    path="${path/#\~/$HOME}"
    printf '%s\n' "$path"
}
