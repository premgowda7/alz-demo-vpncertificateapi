#!/usr/bin/env bash

###############################################################################
#  packet_filter.sh
#
#  Purpose:
#      Configure Linux iptables and NFQUEUE for OpenVPN packet filtering.
#
#  Responsibilities:
#
#      • Create dedicated PACKET_FILTER chain
#      • Attach PACKET_FILTER to FORWARD chain
#      • Restrict whitelist API manager (INPUT, API_PORT) to DM EU only
#      • Backup current firewall
#      • Configure NFQUEUE
#      • Configure DoS protection
#      • Remove firewall rules safely
#      • Restore previous firewall
#      • Display firewall status
#
#  Usage:
#
#      sudo ./packet_filter.sh setup
#      sudo ./packet_filter.sh remove
#      sudo ./packet_filter.sh status
#      sudo ./packet_filter.sh restore <backup_file>
#
###############################################################################

set -euo pipefail

###############################################################################
# Configuration
###############################################################################

readonly CHAIN_NAME="PACKET_FILTER"
readonly INPUT_CHAIN_NAME="PACKET_FILTER_INPUT"

# Defaults shown when prompting; actual values are collected via prompt_config()
DM_IN="10.9.0.10"
CONTROLS_IN="10.9.0.20"
DM_EU="10.8.0.30"

# Populated by detect_openvpn_server_ip() from /etc/openvpn/server.conf
OPENVPN_SERVER_IP=""

API_PORT=8000

QUEUE_NUM=5

#
# Maximum NEW connections per source IP
#
readonly HASHLIMIT_RATE="100/second"
readonly HASHLIMIT_BURST=200

#
# Maximum concurrent TCP connections
#
readonly CONNLIMIT=500

#
# Backup location
#
readonly BACKUP_DIR="/var/backups"

#
# Log prefix
#
readonly LOG_PREFIX="[PACKET_FILTER]"

###############################################################################
# Colors
###############################################################################

RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
BLUE=$'\033[34m'
RESET=$'\033[0m'

###############################################################################
# Logging Helpers
###############################################################################

log_info()
{
    printf '%s[INFO]%s %s\n' "$GREEN" "$RESET" "$*"
}

log_warn()
{
    printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*"
}

log_error()
{
    printf '%s[ERROR]%s %s\n' "$RED" "$RESET" "$*"
}

log_step()
{
    echo
    printf '%s======================================================\n' "$BLUE"
    echo "$*"
    printf '======================================================%s\n' "$RESET"
}

###############################################################################
# Detect OpenVPN Server IP
#
# Reads the local "server" directive from /etc/openvpn/server.conf (network
# address + subnet mask) and derives the server's own tun0 IP (network
# address + 1), so the whitelist API manager stays reachable from the
# OpenVPN server itself regardless of region (EU/IN/etc).
###############################################################################

detect_openvpn_server_ip()
{
    local conf_file="/etc/openvpn/server.conf"
    local line network_addr n1 n2 n3 n4

    [[ -f "$conf_file" ]] || return

    line=$(grep -E '^server ' "$conf_file" | head -n1)
    [[ -n "$line" ]] || return

    network_addr=$(awk '{print $2}' <<< "$line")
    IFS=. read -r n1 n2 n3 n4 <<< "$network_addr"

    if [[ "$n4" -lt 255 ]]
    then
        OPENVPN_SERVER_IP="$n1.$n2.$n3.$((n4+1))"
    else
        OPENVPN_SERVER_IP="$network_addr"
    fi
}

###############################################################################
# Interactive Configuration
###############################################################################

prompt_config()
{
    log_step "Configuration"

    local input

    read -rp "DM IN address [${DM_IN}]: " input
    DM_IN="${input:-$DM_IN}"

    read -rp "Controls IN address [${CONTROLS_IN}]: " input
    CONTROLS_IN="${input:-$CONTROLS_IN}"

    read -rp "DM EU address [${DM_EU}]: " input
    DM_EU="${input:-$DM_EU}"

    read -rp "OpenVPN server address [${OPENVPN_SERVER_IP}]: " input
    OPENVPN_SERVER_IP="${input:-$OPENVPN_SERVER_IP}"

    read -rp "API port [${API_PORT}]: " input
    API_PORT="${input:-$API_PORT}"

    read -rp "NFQUEUE number [${QUEUE_NUM}]: " input
    QUEUE_NUM="${input:-$QUEUE_NUM}"
}

###############################################################################
# Root Validation
###############################################################################

require_root()
{
    if [[ "$EUID" -ne 0 ]]
    then
        log_error "This script must be run as root."

        echo
        echo "Example:"
        echo "sudo ./packet_filter.sh setup"
        echo

        exit 1
    fi
}

###############################################################################
# Dependency Validation
###############################################################################

require_command()
{
    local cmd="$1"

    if ! command -v "$cmd" >/dev/null 2>&1
    then
        log_error "$cmd is not installed."

        exit 1
    fi
}

check_dependencies()
{
    log_step "Checking required commands"

    require_command iptables
    require_command iptables-save
    require_command iptables-restore
    require_command modprobe
    require_command sysctl

    log_info "All required commands are available."
}

###############################################################################
# Kernel Modules
###############################################################################

load_kernel_modules()
{
    log_step "Loading kernel modules"
    modprobe nf_conntrack
    modprobe nfnetlink_queue
    log_info "nf_conntrack loaded"
    log_info "nfnetlink_queue loaded"
}

###############################################################################
# Enable IP Forwarding
###############################################################################

enable_ip_forwarding()
{
    log_step "Checking IPv4 forwarding"
    local current
    current=$(sysctl -n net.ipv4.ip_forward)
    if [[ "$current" == "1" ]]
    then
        log_info "IPv4 forwarding already enabled."
        return
    fi

    log_warn "IPv4 forwarding disabled."
    sysctl -w net.ipv4.ip_forward=1
    log_info "IPv4 forwarding enabled."
}

###############################################################################
# Backup Existing Firewall
###############################################################################

backup_firewall()
{
    log_step "Backing up current firewall"
    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="${BACKUP_DIR}/iptables-$(date +%Y%m%d-%H%M%S).rules"
    iptables-save > "$BACKUP_FILE"
    log_info "Firewall backup created."
    echo
    echo "Backup:"
    echo "$BACKUP_FILE"
    echo
}

###############################################################################
# Restore Firewall
###############################################################################

restore_firewall()
{
    local backup="$1"
    if [[ ! -f "$backup" ]]
    then
        log_error "Backup not found."
        exit 1
    fi
    log_step "Restoring firewall"
    iptables-restore < "$backup"
    log_info "Firewall restored successfully."
}

###############################################################################
# Chain Helpers
###############################################################################

chain_exists()
{
    local chain="${1:-$CHAIN_NAME}"
    iptables -L "$chain" >/dev/null 2>&1
}

rule_exists()
{
    iptables -C "$@" >/dev/null 2>&1
}

###############################################################################
# Create Dedicated Chain
###############################################################################

create_chain()
{
    log_step "Creating dedicated chain"
    if chain_exists
    then
        log_info "Chain ${CHAIN_NAME} already exists."
    else
        iptables -N "$CHAIN_NAME"
        log_info "Chain ${CHAIN_NAME} created."
    fi

    #
    # Attach chain to FORWARD at the top so DM_IN/CONTROLS_IN NFQUEUE
    # verdicts run before any other FORWARD rule (e.g. disable_openvpn_mesh.sh
    # ACCEPT rules) can short-circuit them, regardless of script run order.
    #

    if rule_exists FORWARD -j "$CHAIN_NAME"
    then
        log_info "FORWARD already jumps to ${CHAIN_NAME}"
    else
        iptables -I FORWARD 1 -j "$CHAIN_NAME"
        log_info "FORWARD → ${CHAIN_NAME} attached"
    fi
}

###############################################################################
# Flush Chain
###############################################################################

flush_chain()
{
    if chain_exists
    then
        log_step "Flushing ${CHAIN_NAME}"
        iptables -F "$CHAIN_NAME"
        log_info "Chain flushed."
    fi
}

###############################################################################
# Delete Chain
###############################################################################

delete_chain()
{
    if ! chain_exists
    then
        log_warn "${CHAIN_NAME} does not exist."
        return
    fi

    log_step "Deleting ${CHAIN_NAME}"

    # Remove jump from FORWARD
    if rule_exists FORWARD -j "$CHAIN_NAME"
    then
        iptables -D FORWARD -j "$CHAIN_NAME"
    fi

    # Flush rules
    iptables -F "$CHAIN_NAME"

    # Delete chain
    iptables -X "$CHAIN_NAME"
    log_info "${CHAIN_NAME} removed."
}

###############################################################################
# Create Dedicated INPUT Chain
#
# Restricts access to the whitelist API manager (listening on API_PORT on
# this host) so only DM EU can reach it directly. This is separate from the
# FORWARD-side PACKET_FILTER chain, which only governs traffic routed
# THROUGH this host, not traffic destined TO this host itself.
###############################################################################

create_input_chain()
{
    log_step "Creating dedicated INPUT chain"
    if chain_exists "$INPUT_CHAIN_NAME"
    then
        log_info "Chain ${INPUT_CHAIN_NAME} already exists."
    else
        iptables -N "$INPUT_CHAIN_NAME"
        log_info "Chain ${INPUT_CHAIN_NAME} created."
    fi

    if rule_exists INPUT -j "$INPUT_CHAIN_NAME"
    then
        log_info "INPUT already jumps to ${INPUT_CHAIN_NAME}"
    else
        iptables -I INPUT 1 -j "$INPUT_CHAIN_NAME"
        log_info "INPUT → ${INPUT_CHAIN_NAME} attached"
    fi
}

###############################################################################
# Flush INPUT Chain
###############################################################################

flush_input_chain()
{
    if chain_exists "$INPUT_CHAIN_NAME"
    then
        log_step "Flushing ${INPUT_CHAIN_NAME}"
        iptables -F "$INPUT_CHAIN_NAME"
        log_info "Chain flushed."
    fi
}

###############################################################################
# Delete INPUT Chain
###############################################################################

delete_input_chain()
{
    if ! chain_exists "$INPUT_CHAIN_NAME"
    then
        log_warn "${INPUT_CHAIN_NAME} does not exist."
        return
    fi

    log_step "Deleting ${INPUT_CHAIN_NAME}"

    # Remove jump from INPUT
    if rule_exists INPUT -j "$INPUT_CHAIN_NAME"
    then
        iptables -D INPUT -j "$INPUT_CHAIN_NAME"
    fi

    # Flush rules
    iptables -F "$INPUT_CHAIN_NAME"

    # Delete chain
    iptables -X "$INPUT_CHAIN_NAME"
    log_info "${INPUT_CHAIN_NAME} removed."
}

###############################################################################
# Add Rule Helper
###############################################################################
# Adds a rule only if it does not already exist.
# Example:
# add_rule PACKET_FILTER -j ACCEPT
###############################################################################

add_rule()
{
    local chain="$1"
    shift
    if rule_exists "$chain" "$@"
    then
        log_info "Rule already exists: $chain $*"
    else
        iptables -A "$chain" "$@"
        log_info "Rule added: $chain $*"
    fi
}

###############################################################################
# Rule 1
# ACCEPT ESTABLISHED,RELATED
###############################################################################

add_established_rule()
{
    log_step "Adding ESTABLISHED/RELATED rule"

    add_rule \
        "$CHAIN_NAME" \
        -m conntrack \
        --ctstate ESTABLISHED,RELATED \
        -j ACCEPT
}

###############################################################################
# Rule 2
# Allow DM EU API traffic
###############################################################################

add_dm_eu_rule()
{
    log_step "Adding DM EU API rule"
    add_rule \
        "$CHAIN_NAME" \
        -p tcp \
        -s "$DM_EU" \
        --dport "$API_PORT" \
        -j ACCEPT
}

###############################################################################
# Rule 2b
# Always allow DM IN -> DM EU traffic (any protocol/port), so DM is never
# locked out of reaching its own management API by the whitelist/NFQUEUE.
###############################################################################

add_dm_in_to_dm_eu_rule()
{
    log_step "Adding DM IN -> DM EU always-allow rule"
    add_rule \
        "$CHAIN_NAME" \
        -s "$DM_IN" \
        -d "$DM_EU" \
        -j ACCEPT
}

###############################################################################
# DoS Protection
# Limit NEW connection rate per source IP.
# hashlimit keeps a separate bucket for each source IP.
###############################################################################

add_hashlimit_rule()
{
    log_step "Adding hashlimit rule"
    # --hashlimit-above (not --hashlimit/--hashlimit-upto) so this rule only
    # matches traffic EXCEEDING the rate and drops it; traffic within the
    # limit doesn't match at all and falls through to the DM_IN/CONTROLS_IN
    # NFQUEUE rules below. (A prior -j RETURN here matched normal-rate
    # traffic and exited PACKET_FILTER entirely, back to FORWARD, before it
    # ever reached the whitelist check.)
    add_rule \
        "$CHAIN_NAME" \
        -m conntrack \
        --ctstate NEW \
        -m hashlimit \
        --hashlimit-name PACKET_FILTER_LIMIT \
        --hashlimit-mode srcip \
        --hashlimit-above "$HASHLIMIT_RATE" \
        --hashlimit-burst "$HASHLIMIT_BURST" \
        -j DROP
}

###############################################################################
# Connection Limit
# Prevent excessive simultaneous TCP connections.
###############################################################################

add_connlimit_rule()
{
    log_step "Adding connlimit rule"
    add_rule \
        "$CHAIN_NAME" \
        -p tcp \
        -m connlimit \
        --connlimit-above "$CONNLIMIT" \
        -j DROP
}

###############################################################################
# INPUT Rule 1
# Allow DM EU to reach the whitelist API manager (API_PORT) on this host.
###############################################################################

add_api_port_allow_dm_eu_rule()
{
    log_step "Adding API port allow rule for DM EU"
    add_rule \
        "$INPUT_CHAIN_NAME" \
        -p tcp \
        -s "$DM_EU" \
        --dport "$API_PORT" \
        -j ACCEPT
}

###############################################################################
# INPUT Rule 1b
# Allow the local OpenVPN server itself to reach the whitelist API manager.
# Skipped if no server IP was detected/entered.
###############################################################################

add_api_port_allow_openvpn_server_rule()
{
    if [[ -z "$OPENVPN_SERVER_IP" ]]
    then
        log_warn "No OpenVPN server IP detected; skipping API port allow rule for it."
        return
    fi

    log_step "Adding API port allow rule for OpenVPN server"
    add_rule \
        "$INPUT_CHAIN_NAME" \
        -p tcp \
        -s "$OPENVPN_SERVER_IP" \
        --dport "$API_PORT" \
        -j ACCEPT
}

###############################################################################
# INPUT Rule 2
# Block every other client from reaching the whitelist API manager.
# Must come after the DM EU / OpenVPN server allow rules above so their
# traffic matches first and is never reached by this DROP.
###############################################################################

add_api_port_block_rule()
{
    log_step "Adding API port block rule for all other clients"
    add_rule \
        "$INPUT_CHAIN_NAME" \
        -p tcp \
        --dport "$API_PORT" \
        -j DROP
}

###############################################################################
# INPUT RETURN
# Return control to INPUT chain for all other traffic/ports.
###############################################################################

add_input_return_rule()
{
    log_step "Adding INPUT RETURN rule"
    add_rule \
        "$INPUT_CHAIN_NAME" \
        -j RETURN
}

###############################################################################
# Rule 3
# DM IN → NFQUEUE
###############################################################################

add_dm_in_rule()
{
    log_step "Adding DM IN NFQUEUE rule"
    add_rule \
        "$CHAIN_NAME" \
        -s "$DM_IN" \
        -m conntrack \
        --ctstate NEW \
        -j NFQUEUE \
        --queue-num "$QUEUE_NUM"
}

###############################################################################
# Rule 4
#
# Controls IN → NFQUEUE
#
###############################################################################

add_controls_rule()
{
    log_step "Adding Controls IN NFQUEUE rule"
    add_rule \
        "$CHAIN_NAME" \
        -s "$CONTROLS_IN" \
        -m conntrack \
        --ctstate NEW \
        -j NFQUEUE \
        --queue-num "$QUEUE_NUM"
}

###############################################################################
# Logging
# Log packets that reach the end of our chain.
# Logging is rate limited to avoid flooding kernel logs.
###############################################################################

add_logging_rule()
{
    log_step "Adding logging rule"
    add_rule \
        "$CHAIN_NAME" \
        -m limit \
        --limit 10/minute \
        --limit-burst 20 \
        -j LOG \
        --log-prefix "${LOG_PREFIX} "
}

###############################################################################
# RETURN
# Return control to FORWARD chain.
###############################################################################

add_return_rule()
{
    log_step "Adding RETURN rule"
    add_rule \
        "$CHAIN_NAME" \
        -j RETURN
}

###############################################################################
# Verify Rules
###############################################################################

verify_rules()
{
    log_step "Installed PACKET_FILTER chain"
    iptables -L "$CHAIN_NAME" \
        -n \
        -v \
        --line-numbers
    echo
    log_step "FORWARD chain"
    iptables -L FORWARD \
        -n \
        -v \
        --line-numbers
    echo
    log_step "Installed PACKET_FILTER_INPUT chain"
    iptables -L "$INPUT_CHAIN_NAME" \
        -n \
        -v \
        --line-numbers
    echo
    log_step "INPUT chain"
    iptables -L INPUT \
        -n \
        -v \
        --line-numbers
}

###############################################################################
# Setup Firewall
###############################################################################

setup_firewall()
{
    log_step "Starting firewall configuration"
    require_root
    detect_openvpn_server_ip
    prompt_config
    check_dependencies
    load_kernel_modules
    enable_ip_forwarding
    backup_firewall
    create_chain
    create_input_chain

    
    # Remove any existing rules from our chain.
    # This ensures a clean rebuild every time.

    flush_chain
    flush_input_chain

    # Build chain in required order.
    add_established_rule
    add_dm_eu_rule
    add_dm_in_to_dm_eu_rule
    add_hashlimit_rule
    add_connlimit_rule
    add_dm_in_rule
    add_controls_rule
    add_logging_rule
    add_return_rule

    # Build INPUT chain: only DM EU and the OpenVPN server may reach the
    # whitelist API manager.
    add_api_port_allow_dm_eu_rule
    add_api_port_allow_openvpn_server_rule
    add_api_port_block_rule
    add_input_return_rule
    verify_rules
    echo
    log_info "Firewall successfully configured."
}

###############################################################################
# Remove Firewall
###############################################################################

remove_firewall()
{
    log_step "Removing firewall configuration"
    require_root
    check_dependencies
    delete_chain
    delete_input_chain
    log_info "Firewall successfully removed."
}

###############################################################################
# Firewall Status
###############################################################################

status()
{
    log_step "PACKET_FILTER Chain"

    if chain_exists
    then
        iptables -L "$CHAIN_NAME" \
            -n \
            -v \
            --line-numbers
    else
        log_warn "Chain ${CHAIN_NAME} does not exist."
    fi

    echo
    log_step "FORWARD Chain"
    iptables -L FORWARD \
        -n \
        -v \
        --line-numbers

    echo
    log_step "PACKET_FILTER_INPUT Chain"

    if chain_exists "$INPUT_CHAIN_NAME"
    then
        iptables -L "$INPUT_CHAIN_NAME" \
            -n \
            -v \
            --line-numbers
    else
        log_warn "Chain ${INPUT_CHAIN_NAME} does not exist."
    fi

    echo
    log_step "INPUT Chain"
    iptables -L INPUT \
        -n \
        -v \
        --line-numbers
    echo
    log_step "Loaded Kernel Modules"
    lsmod | grep -E "nf_conntrack|nfnetlink_queue" || true
    echo
    log_step "IP Forwarding"
    sysctl net.ipv4.ip_forward
}

###############################################################################
# Usage
###############################################################################

usage()
{
cat <<EOF

Usage:

    sudo ./packet_filter.sh setup
        Configure firewall rules.

    sudo ./packet_filter.sh remove
        Remove PACKET_FILTER chain.

    sudo ./packet_filter.sh status
        Show firewall status.

    sudo ./packet_filter.sh restore <backup_file>
        Restore firewall from backup.

Examples:

    sudo ./packet_filter.sh setup
    sudo ./packet_filter.sh status
    sudo ./packet_filter.sh remove
    sudo ./packet_filter.sh restore \
        /var/backups/iptables-20260812-153000.rules

EOF
}

###############################################################################
# Main
###############################################################################

main()
{
    local action="${1:-}"

    case "$action" in

        setup)

            setup_firewall
            ;;

        remove)

            remove_firewall
            ;;

        status)

            status
            ;;

        restore)

            if [[ $# -ne 2 ]]
            then
                log_error "Backup file missing."

                usage

                exit 1
            fi

            require_root

            restore_firewall "$2"
            ;;

        help|-h|--help)

            usage
            ;;

        *)

            log_error "Unknown command."

            usage

            exit 1
            ;;

    esac
}

###############################################################################
# Script Entry Point
###############################################################################

main "$@"