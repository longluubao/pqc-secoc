#!/usr/bin/env bash
# scripts/link_eth0.sh — put eth0 of this Raspberry Pi into the state the two-node experiments
# need, and take it out again. Runs ON the Pi. Runtime settings only: nothing survives a reboot,
# nothing is written under /etc, wlan0 and the default route are not touched.
#
#   scripts/link_eth0.sh up <address> [1000|100]   e.g. up 10.10.10.1 100
#   scripts/link_eth0.sh speed <1000|100>          steps 1 and 2 of up only, no waiting, no check
#   scripts/link_eth0.sh down <address>
#   scripts/link_eth0.sh status
#
# up, in this order (every changing command is printed with a leading "+", and is skipped when
# the state is already as wanted):
#   1. Energy-Efficient Ethernet off. With EEE active the bcmgenet receive path of these kernels
#      stalls (CVE-2026-64125, "net: bcmgenet: keep RBUF EEE/PM disabled").
#   2. speed: autonegotiation stays ON; for 100 only 100baseT/Full is advertised (mask 0x008),
#      for 1000 everything the PHY supports.
#   3. NetworkManager is told to ignore eth0: /run/NetworkManager/conf.d/90-eth0-unmanaged.conf
#      plus `nmcli general reload`. Without this NM starts DHCP on eth0 after every carrier change
#      and removes the manual address when DHCP times out (45 s). On a freshly booted board, where
#      NM still holds eth0, letting go of it drops the carrier for a few seconds, and NM may leave
#      the interface administratively down: it is set up again.
#   4. wait for the carrier at the wanted speed; EEE is read again and switched off again if the
#      renegotiation brought it back.
#   5. the address.
#   6. check: the link is settled (wanted speed, full duplex, no carrier change for 3 s, within
#      15 s; carrier_changes at the start of the step and at its end are printed), address present,
#      NM "unmanaged", EEE "disabled". Exit 1 otherwise.
# The negotiated speed is the best mode BOTH ends advertise, so to go from 100 to 1000 the first
# board gets `speed 1000` (it cannot see 1000 yet), then the second `up`, then the first `up`.
# down: removes the NM file (and reloads), deletes the address, advertises all supported modes.
#   EEE is left off; to switch it back on:  sudo ethtool --set-eee eth0 eee on
#   (a reboot restores everything).

set -uo pipefail
IF=eth0
ETHTOOL=/usr/sbin/ethtool
NM_CONF=/run/NetworkManager/conf.d/90-eth0-unmanaged.conf

run() { echo "+ $*"; "$@"; }

# ethtool link-mode names -> advertise mask
mask_of() {
    local m=0 name
    for name in "$@"; do
        case "${name}" in
            10baseT/Half)   m=$(( m | 0x001 )) ;;
            10baseT/Full)   m=$(( m | 0x002 )) ;;
            100baseT/Half)  m=$(( m | 0x004 )) ;;
            100baseT/Full)  m=$(( m | 0x008 )) ;;
            1000baseT/Half) m=$(( m | 0x010 )) ;;
            1000baseT/Full) m=$(( m | 0x020 )) ;;
        esac
    done
    printf '0x%03x' "${m}"
}
modes() { ${ETHTOOL} ${IF} 2>/dev/null | sed -n "/$1 link modes/,/$1 pause/p" | grep -oE '[0-9]+baseT/(Half|Full)'; }
eee()   { sudo -n ${ETHTOOL} --show-eee ${IF} 2>/dev/null | sed -n 's/^[[:space:]]*EEE status: //p'; }
nm_state() { nmcli -t -f DEVICE,STATE device status | sed -n "s/^${IF}://p"; }

wait_carrier() {    # <speed>
    local i
    for i in $(seq 100); do
        [[ "$(cat /sys/class/net/${IF}/carrier 2>/dev/null)" == 1 && "$(cat /sys/class/net/${IF}/speed 2>/dev/null)" == "$1" ]] && return 0
        sleep 0.2
    done
    echo "no carrier at $1 Mbit/s after 20 s" >&2
    return 1
}

# the wanted speed at full duplex with no carrier change for 3 s, within 15 s
wait_settled() {    # <speed>
    local i cc last="" stable=0
    for i in $(seq 75); do
        cc="$(cat /sys/class/net/${IF}/carrier_changes)"
        if [[ "$(cat /sys/class/net/${IF}/carrier 2>/dev/null)" == 1 && "$(cat /sys/class/net/${IF}/speed 2>/dev/null)" == "$1" &&
              "$(cat /sys/class/net/${IF}/duplex 2>/dev/null)" == full && "${cc}" == "${last}" ]]; then
            stable=$(( stable + 1 ))
        else
            stable=0
        fi
        last="${cc}"
        (( stable >= 15 )) && return 0
        sleep 0.2
    done
    return 1
}

status() {
    echo "speed=$(cat /sys/class/net/${IF}/speed 2>/dev/null) duplex=$(cat /sys/class/net/${IF}/duplex 2>/dev/null) autoneg=$(${ETHTOOL} ${IF} 2>/dev/null | sed -n 's/^[[:space:]]*Auto-negotiation: //p')"
    echo "advertised=$(modes Advertised | tr '\n' ' ')"
    echo "eee=$(eee)"
    echo "addr=$(ip -4 -br addr show dev ${IF} | awk '{print $3}')"
    echo "nm=$(nm_state)"
    echo "carrier_changes=$(cat /sys/class/net/${IF}/carrier_changes)"
    echo "default_route=$(ip route show default | head -1)"
}

# steps 1 and 2: EEE off, advertised modes for the wanted speed
set_speed() {
    local want
    case "$1" in
        100)  want=0x008 ;;
        1000) want="$(mask_of $(modes Supported))" ;;
        *) echo "speed must be 1000 or 100" >&2; exit 2 ;;
    esac
    [[ "$(eee)" == disabled ]] || run sudo -n ${ETHTOOL} --set-eee ${IF} eee off
    [[ "$(mask_of $(modes Advertised))" == "${want}" ]] || run sudo -n ${ETHTOOL} -s ${IF} advertise "${want}"
}

case "${1:-}" in
speed)
    set_speed "${2:?speed}"
    ;;

up)
    ADDR="${2:?address}"; SPEED="${3:-1000}"
    CC_BEFORE="$(cat /sys/class/net/${IF}/carrier_changes)"
    set_speed "${SPEED}"

    if [[ "$(nm_state)" != unmanaged ]]; then
        if [[ ! -f "${NM_CONF}" ]]; then
            run sudo -n mkdir -p "$(dirname "${NM_CONF}")"
            echo "+ write ${NM_CONF}: [keyfile] unmanaged-devices=interface-name:${IF}"
            printf '[keyfile]\nunmanaged-devices=interface-name:%s\n' "${IF}" | sudo -n tee "${NM_CONF}" > /dev/null
        fi
        run sudo -n nmcli general reload
        for i in $(seq 25); do [[ "$(nm_state)" == unmanaged ]] && break; sleep 0.2; done
        # NM drops the carrier when it lets go of a device it held (seen after a reboot, 2026-11-23:
        # speed read -1 right after the reload); give the drop time to show before waiting for the link
        sleep 2
    fi
    # ... and it can leave the interface administratively down (seen 2026-11-23 on a board whose eth0
    # NM held as "disconnected": no carrier on either end afterwards)
    (( $(cat /sys/class/net/${IF}/flags) & 1 )) || run sudo -n ip link set ${IF} up

    wait_carrier "${SPEED}" || { status; exit 1; }
    if [[ "$(eee)" != disabled ]]; then
        run sudo -n ${ETHTOOL} --set-eee ${IF} eee off
        sleep 1
        wait_carrier "${SPEED}" || exit 1
    fi

    # after NM has let go: it takes its address with it
    ip -4 addr show dev ${IF} | grep -q " ${ADDR}/24 " || run sudo -n ip addr replace "${ADDR}/24" dev ${IF}

    SETTLED=yes; wait_settled "${SPEED}" || SETTLED=no
    status
    echo "carrier_changes_before=${CC_BEFORE} settled=${SETTLED}"
    [[ "${SETTLED}" == yes ]] || { echo "FAIL: link not settled at ${SPEED} Mbit/s full duplex (no carrier change for 3 s) within 15 s" >&2; exit 1; }
    ip -4 addr show dev ${IF} | grep -q " ${ADDR}/24 " || { echo "FAIL: ${ADDR} not on ${IF}" >&2; exit 1; }
    [[ "$(nm_state)" == unmanaged ]] || { echo "FAIL: NetworkManager state of ${IF} is '$(nm_state)', not unmanaged" >&2; exit 1; }
    [[ "$(eee)" == disabled ]] || { echo "FAIL: EEE is '$(eee)', not disabled" >&2; exit 1; }
    [[ "$(cat /sys/class/net/${IF}/speed)" == "${SPEED}" ]] || { echo "FAIL: speed is not ${SPEED}" >&2; exit 1; }
    ;;

down)
    ADDR="${2:?address}"
    if [[ -f "${NM_CONF}" ]]; then
        run sudo -n rm "${NM_CONF}"
        run sudo -n nmcli general reload
    fi
    ip -4 addr show dev ${IF} | grep -q " ${ADDR}/24 " && run sudo -n ip addr del "${ADDR}/24" dev ${IF}
    WANT="$(mask_of $(modes Supported))"
    [[ "$(mask_of $(modes Advertised))" == "${WANT}" ]] || run sudo -n ${ETHTOOL} -s ${IF} advertise "${WANT}"
    sleep 3
    status
    echo "EEE left as it is; to switch it on again: sudo ethtool --set-eee ${IF} eee on"
    ;;

status)
    status
    ;;

*)
    sed -n '2,10p' "${BASH_SOURCE[0]}" >&2
    exit 2
    ;;
esac
