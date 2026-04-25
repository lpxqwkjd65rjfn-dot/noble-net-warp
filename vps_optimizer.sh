#!/bin/bash
# shellcheck disable=SC2059

# ==============================================================================
# VPS Global Optimization Script (v8.1.1 PHOENIX-Z+)
# ------------------------------------------------------------------------------
# Phase 1 — Correctness on locked-down rented VPS:
#   - Hypervisor / container detection (KVM / OpenVZ / LXC / Docker / native)
#   - Probe-then-write for every sysctl & sysfs knob (no broken /etc/sysctl.d
#     entries, no failing oneshot units after reboot)
#   - Kernel-version gate (MPTCP, BBR2/3, gro_flush_timeout, etc.)
#   - Self-test report after apply (OK / SKIPPED / DENIED for each setting)
#
# Phase 2 — Multi-core load distribution:
#   - RPS + RFS (correct bitmask for >32 cores)
#   - XPS (Transmit Packet Steering) — was missing in v6.1
#   - IRQ affinity spreading via /proc/irq/*/smp_affinity_list (when writable)
#   - flow_limit_table_len + flow_limit_cpu_bitmap
#   - sched_autogroup_enabled=0, migration_cost, NAPI defer
#   - CPU governor → performance (best effort, silent fallback)
#
# Phase 3 — Real proxy bottlenecks:
#   - conntrack tuning (max=1M, hashsize=256k, timeout-tuned for proxies)
#   - MPTCP enabled when supported
#   - BBR pacing tuned (pacing_ss_ratio, pacing_ca_ratio, min_rtt_wlen)
#   - tcp_min_snd_mss, tcp_max_orphans, tcp_collapse_max_bytes
#   - accept_redirects/send_redirects/source_route hardening
#
# Phase 4 — Memory / I/O:
#   - Transparent Huge Pages → madvise (no latency spikes)
#   - I/O scheduler: none for NVMe, mq-deadline for SSD
#   - nr_requests / read_ahead_kb tuning
#   - inotify watches/instances raised
#   - core_pattern → /dev/null (no disk fill on crash)
#
# Phase 6 — UX:
#   - Profile presets: balanced / proxy / web (different sysctl mixes)
#   - Status dashboard (BBR, qdisc, conntrack usage, ZRAM, fds, noise)
#   - Non-interactive CLI: apply / status / noise on|off|edit / preset / reset
#                         / dry-run / self-test / export / import / update
#   - dry-run mode: shows everything that WOULD change without touching system
#   - Self-update from GitHub
#
# Inherited from v6.0/v6.1:
#   - Adaptive TCP/UDP buffers scaled with RAM
#   - LRO off, ring buffers maxed, adaptive coalescence
#   - File descriptor limits (limits.conf + systemd defaults)
#   - ZRAM (zstd → lz4 fallback)
#   - Persistent RPS/XPS via systemd
#   - iOS Stealth noise + RU human profile (Yandex/Mail.ru/Max.ru/news)
#     + APT phantom (libs + OS images → /dev/null)
#   - All noise parameters in /etc/vps-noise.conf
# ==============================================================================

set -o pipefail

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'

SYSCTL_CONF="/etc/sysctl.d/99-vps-optimizer.conf"
LIMITS_CONF="/etc/security/limits.d/99-vps-limits.conf"
NOISE_GEN_SCRIPT="/usr/local/bin/vps_noise_gen.sh"
NOISE_GEN_SERVICE="/etc/systemd/system/vps-noise.service"
RPS_BOOT_SCRIPT="/usr/local/sbin/vps_rps_boot.sh"
RPS_BOOT_SERVICE="/etc/systemd/system/vps-rps.service"
EXP_CONF="/etc/sysctl.d/99-vps-experimental.conf"
SYSCTL_BACKUP="/etc/sysctl.d/.99-vps-optimizer.bak"
NOISE_CONF="/etc/vps-noise.conf"
PRESET_FILE="/etc/vps-optimizer.preset"
DNS_CONF="/etc/systemd/resolved.conf.d/99-vps-optimizer.conf"
DNS_STATE="/etc/vps-optimizer.dns"
DNS_RESOLV_BACKUP="/etc/.vps_optimizer_resolv_backup"
SELF_URL="https://raw.githubusercontent.com/lpxqwkjd65rjfn-dot/noble-net-warp/main/vps_optimizer.sh"
SELF_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
RUN_LOG="/var/log/vps-optimizer.log"

# Глобальные флаги (управляются через CLI)
DRY_RUN=0
QUIET=0
PRESET=""

# Сводки sysctl/sysfs/ethtool — заполняются в процессе apply, печатаются в self_test
SYSCTL_OK=()
SYSCTL_SKIP=()
SYSFS_OK=()
SYSFS_SKIP=()

print_header() {
    [ "$QUIET" = "1" ] && return
    clear
    echo -e "${MAGENTA}${BOLD}"
    echo "================================================================="
    echo "       ULTRA VPS ACCELERATOR v8.1.1 (PHOENIX-Z+)                   "
    echo "================================================================="
    echo -e "  Probe-then-Write | XPS+RPS+IRQ | conntrack | MPTCP | THP    "
    echo -e "  Presets: balanced / proxy / web    Stealth: iOS+RU+APT     "
    echo -e "=================================================================${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Запустите от имени root.${NC}"
        exit 1
    fi
}

# Лог в файл (перезаписывается при каждом запуске apply, рядом — на консоль)
_log() {
    local level="$1"; shift
    local msg="$*"
    [ "$QUIET" = "1" ] || echo -e "$msg"
    echo "[$(date -u +%FT%TZ)] [$level] $(echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g')" >> "$RUN_LOG" 2>/dev/null || true
}

# ===================================================================
#  Хелперы детектирования среды
# ===================================================================

# Возвращает: kvm / xen / openvz / lxc / docker / wsl / none
detect_virt() {
    local v=""
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        v=$(systemd-detect-virt 2>/dev/null || echo none)
    fi
    [ -z "$v" ] && v="none"
    echo "$v"
}

# Парсим ядро в число "MAJORMINORPATCH" для версионных гейтов
kernel_version_int() {
    local kv
    kv=$(uname -r | awk -F'[.-]' '{printf "%d%02d%02d", $1, $2, ($3==""?0:$3)}')
    echo "$kv"
}

# Поддерживается ли sysctl (есть ли соответствующий файл в /proc/sys/...)?
kernel_supports_sysctl() {
    local key="$1"
    [ -e "/proc/sys/${key//.//}" ]
}

# Доступен ли congestion control в ядре?
has_cong_ctl() {
    local algo="$1"
    grep -qw "$algo" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null
}

# Безопасная запись sysctl: probe-then-persist.
# Сначала пробуем `sysctl -w` в память, и только при успехе добавляем в
# `$SYSCTL_CONF`. Если ядро не знает ключ — тихо скипаем (важно на OpenVZ).
SYSCTL_TMP=""
sysctl_safe() {
    local key="$1" value="$2"
    if ! kernel_supports_sysctl "$key"; then
        SYSCTL_SKIP+=("$key=unsupported")
        return 1
    fi
    if [ "$DRY_RUN" = "1" ]; then
        SYSCTL_OK+=("$key=$value (dry-run)")
        [ -n "$SYSCTL_TMP" ] && echo "$key = $value" >> "$SYSCTL_TMP"
        return 0
    fi
    if sysctl -w "$key=$value" >/dev/null 2>&1; then
        SYSCTL_OK+=("$key=$value")
        [ -n "$SYSCTL_TMP" ] && echo "$key = $value" >> "$SYSCTL_TMP"
        return 0
    else
        SYSCTL_SKIP+=("$key=denied")
        return 1
    fi
}

# Безопасная запись в /sys или /proc: проверяем существование и writability.
sysfs_safe() {
    local path="$1" value="$2"
    if [ ! -e "$path" ]; then
        SYSFS_SKIP+=("$path:missing")
        return 1
    fi
    if [ "$DRY_RUN" = "1" ]; then
        SYSFS_OK+=("$path=$value (dry-run)")
        return 0
    fi
    if echo "$value" > "$path" 2>/dev/null; then
        SYSFS_OK+=("$path=$value")
        return 0
    else
        SYSFS_SKIP+=("$path:denied")
        return 1
    fi
}

# Корректно строим bitmask CPU для rps_cpus, формат группами по 32 бита,
# разделёнными запятыми (старшие биты слева). Работает для >32 ядер.
build_cpu_mask() {
    local n=$1
    if [ "$n" -le 0 ]; then echo "0"; return; fi
    local groups=$(( (n + 31) / 32 ))
    local last_bits=$(( n - (groups - 1) * 32 ))
    local first
    if [ "$last_bits" -ge 32 ]; then
        first="ffffffff"
    else
        first=$(printf '%x' $(( (1 << last_bits) - 1 )))
    fi
    local rest=""
    local i
    for ((i=1; i<groups; i++)); do
        rest=",ffffffff${rest}"
    done
    echo "${first}${rest}"
}

# CPU index → cpumask hex для одного CPU в kernel-формате.
# Формат cpumask — comma-separated 32-bit hex chunks, low-CPU group последним.
# Пример: CPU  0 → "1", CPU 31 → "80000000",
#         CPU 32 → "1,00000000", CPU 63 → "80000000,00000000".
# Для cpu>=32 простое `printf '%x' $((1<<cpu))` ломается на 32-bit ядрах
# и неправильно парсится по cpumask-формату (нужны разделители на каждые 32 бита).
cpu_to_xps_mask() {
    local cpu="${1:-0}"
    [ "$cpu" -lt 0 ] && cpu=0
    local group=$(( cpu / 32 ))
    local bit=$(( cpu % 32 ))
    local val
    val=$(printf '%x' $(( 1 << bit )))
    if [ "$group" -eq 0 ]; then
        echo "$val"
    else
        local zeros="" i
        for ((i=0; i<group; i++)); do zeros+=",00000000"; done
        echo "${val}${zeros}"
    fi
}

# Список «реальных» сетевых интерфейсов — без виртуальных оверлеев.
list_real_ifaces() {
    ip -o link show 2>/dev/null | \
        awk -F': ' '$2 !~ /^(lo|virbr|docker|veth|wg|tun|tap|gre|ppp|br-|cilium|kube|cni)/ {print $2}'
}

run_benchmark() {
    clear
    echo -e "${CYAN}${BOLD}=== ТЕСТ ЗАДЕРЖКИ (BENCHMARK) ===${NC}"
    echo "Замеряем средний пинг до глобальных узлов..."

    local targets=("www.google.com" "www.apple.com" "1.1.1.1" "www.cloudflare.com")
    local target ping_res
    for target in "${targets[@]}"; do
        echo -n "Тест $target: "
        ping_res=$(ping -c 4 -W 2 "$target" 2>/dev/null | awk -F '/' 'END {if ($5) print $5; else print ""}')
        if [ -z "$ping_res" ]; then
            echo -e "${RED}ОШИБКА (Timeout)${NC}"
        else
            echo -e "${GREEN}${ping_res} ms${NC}"
        fi
    done

    echo ""
    echo -e "${CYAN}Текущий congestion control:${NC} $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    echo -e "${CYAN}Текущий qdisc по умолчанию:${NC}  $(sysctl -n net.core.default_qdisc 2>/dev/null)"
    echo -e "${CYAN}Доступные алгоритмы:${NC}        $(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)"
    echo ""
    read -r -p "Нажмите Enter..."
}

install_dependencies() {
    echo -e "${YELLOW}[*] Установка компонентов Phoenix...${NC}"
    apt-get update -y
    apt-get install -y --no-install-recommends \
        curl ca-certificates ethtool iproute2 iputils-ping \
        dnsmasq util-linux bc zram-tools jq nano \
        apt-utils dpkg-dev >/dev/null 2>&1

    # Локальный DNS-кэш (dnsmasq) — резко снижает RTT на повторные запросы
    cat > /etc/dnsmasq.d/vps-speed.conf <<EOF
listen-address=127.0.0.1
bind-interfaces
cache-size=10000
no-resolv
neg-ttl=60
min-cache-ttl=60
server=1.1.1.1
server=1.0.0.1
server=8.8.8.8
server=8.8.4.4
EOF
    systemctl restart dnsmasq >/dev/null 2>&1 || true

    echo -e "${GREEN}[+] Базовые компоненты установлены.${NC}"
    echo -e "${YELLOW}[i] Опционально: curl-impersonate-safari даёт TLS/JA3 как у iOS.${NC}"
    echo -e "${YELLOW}    https://github.com/lwthiker/curl-impersonate (release binaries)${NC}"
    sleep 1
}

# ===================================================================
#  Профили (presets)
# ===================================================================
# Каждый пресет — функция, которая выставляет глобальные PRESET_*
# переменные. Дальше apply_*_modules() читают их. Если значение не
# задано — берётся «balanced» по умолчанию.

preset_balanced() {
    PRESET_NAME="balanced"
    PRESET_NOFILE=1048576
    PRESET_BUF_MULT=1
    PRESET_TCP_FASTOPEN=3
    PRESET_TCP_FIN_TIMEOUT=10
    PRESET_TCP_KEEPALIVE_TIME=600
    PRESET_TCP_TW_BUCKETS=1440000
    PRESET_TCP_MAX_ORPHANS=262144
    PRESET_CONNTRACK_MAX=1048576
    PRESET_CONNTRACK_BUCKETS=262144
    PRESET_CONNTRACK_TCP_TIMEOUT=600
    PRESET_NETDEV_BACKLOG=500000
    PRESET_SOMAXCONN=65535
    PRESET_RPS_FLOWS=4096
    PRESET_PORT_RANGE="10000 65535"
    PRESET_ZRAM_FRACTION=50
    PRESET_SWAPPINESS=180
    PRESET_BBR_PACING_SS=200
    PRESET_BBR_PACING_CA=120
}

# Прокси (xray/sing-box/haproxy/nginx-stream/wireguard) — много короткоживущих
# коннектов, агрессивные буферы, гигантский conntrack, максимум fds.
preset_proxy() {
    preset_balanced
    PRESET_NAME="proxy"
    PRESET_NOFILE=2097152
    PRESET_BUF_MULT=2
    PRESET_TCP_FIN_TIMEOUT=8
    PRESET_TCP_KEEPALIVE_TIME=300
    PRESET_TCP_TW_BUCKETS=2000000
    PRESET_TCP_MAX_ORPHANS=524288
    PRESET_CONNTRACK_MAX=2097152
    PRESET_CONNTRACK_BUCKETS=524288
    PRESET_CONNTRACK_TCP_TIMEOUT=300
    PRESET_NETDEV_BACKLOG=1000000
    PRESET_RPS_FLOWS=8192
}

# Web-сервер (nginx/apache, статический контент): меньше conntrack,
# умереннее буферы, security-акценты.
preset_web() {
    preset_balanced
    PRESET_NAME="web"
    PRESET_BUF_MULT=1
    PRESET_TCP_FIN_TIMEOUT=15
    PRESET_TCP_KEEPALIVE_TIME=900
    PRESET_TCP_TW_BUCKETS=720000
    PRESET_CONNTRACK_MAX=524288
    PRESET_CONNTRACK_BUCKETS=131072
    PRESET_CONNTRACK_TCP_TIMEOUT=900
}

load_preset() {
    local p="${1:-}"
    if [ -z "$p" ] && [ -f "$PRESET_FILE" ]; then
        p=$(tr -d '[:space:]' < "$PRESET_FILE" 2>/dev/null)
    fi
    [ -z "$p" ] && p="balanced"
    case "$p" in
        proxy)    preset_proxy ;;
        web)      preset_web ;;
        balanced) preset_balanced ;;
        *)        echo -e "${YELLOW}[!] Неизвестный пресет '$p', использую balanced${NC}"; preset_balanced ;;
    esac
    [ "$DRY_RUN" = "1" ] || echo "$PRESET_NAME" > "$PRESET_FILE" 2>/dev/null || true
    _log INFO "Preset: ${BOLD}${CYAN}${PRESET_NAME}${NC}"
}

# ===================================================================
#  Модули apply_optimizations
# ===================================================================

apply_zram() {
    if ! modprobe zram 2>/dev/null; then
        _log WARN "${YELLOW}[!] ZRAM недоступен (контейнер?) — пропуск.${NC}"
        return 0
    fi
    [ "$DRY_RUN" = "1" ] && { _log INFO "${GRAY}[dry-run] ZRAM пропущен${NC}"; return 0; }
    swapoff /dev/zram0 2>/dev/null || true
    zramctl --reset /dev/zram0 2>/dev/null || true
    local mem_total zram_size
    mem_total=$(free -m | awk '/Mem:/{print $2}')
    zram_size=$(( mem_total * PRESET_ZRAM_FRACTION / 100 ))
    [ "$zram_size" -lt 256 ] && zram_size=256
    zramctl --find --size "${zram_size}M" --algorithm zstd >/dev/null 2>&1 || \
        zramctl --find --size "${zram_size}M" --algorithm lz4 >/dev/null 2>&1
    mkswap /dev/zram0 >/dev/null 2>&1
    swapon /dev/zram0 -p 100 2>/dev/null || true
    _log OK "${GREEN}[+] ZRAM активен (${zram_size}MB).${NC}"
}

# Получаем список ядер, доступных для размещения сетевых очередей,
# исключая isolcpus (если оператор зарезервировал ядра под realtime).
usable_cpus() {
    local total isol
    total=$(nproc)
    isol=$(awk -F'isolcpus=' 'NF>1 {split($2,a," "); print a[1]}' /proc/cmdline 2>/dev/null)
    if [ -z "$isol" ] || ! command -v seq >/dev/null 2>&1; then
        seq 0 $((total-1))
        return
    fi
    # isolcpus может быть "1-3,5" — раскрываем диапазоны.
    local out=() c r a b
    declare -A excluded
    IFS=',' read -ra parts <<<"$isol"
    for r in "${parts[@]}"; do
        if [[ "$r" == *-* ]]; then
            a="${r%-*}"; b="${r#*-}"
            for ((c=a; c<=b; c++)); do excluded[$c]=1; done
        else
            excluded[$r]=1
        fi
    done
    for ((c=0; c<total; c++)); do
        [ -z "${excluded[$c]:-}" ] && out+=("$c")
    done
    printf '%s\n' "${out[@]}"
}

# Тюнинг сетевых интерфейсов: multi-queue, RPS, XPS, RFS, ring buffers,
# coalescence, LRO off, link-speed-aware подстройка буферов.
apply_iface_tuning() {
    local interfaces cpu_cores rps_mask
    interfaces=$(list_real_ifaces)
    cpu_cores=$(nproc)
    rps_mask=$(build_cpu_mask "$cpu_cores")

    if [ -z "$interfaces" ]; then
        _log WARN "${YELLOW}[!] Реальных интерфейсов не найдено — пропуск iface tuning.${NC}"
        return 0
    fi

    sysctl_safe net.core.rps_sock_flow_entries 32768

    # Список реально usable cores (вне isolcpus)
    local usable_arr
    mapfile -t usable_arr < <(usable_cpus)
    local usable_n="${#usable_arr[@]}"
    [ "$usable_n" -eq 0 ] && usable_n=1

    local iface
    for iface in $interfaces; do
        _log INFO "${YELLOW}[*] Iface tuning: $iface (mask=$rps_mask)${NC}"

        # Multi-queue: на virtio-net часто стоит 1 очередь — раскручиваем
        # до min(N_cpus, max_combined). Это даёт реальный multi-core эффект,
        # без него RPS/XPS не «доезжают» до железа.
        if [ "$DRY_RUN" != "1" ]; then
            local mq_max mq_target
            mq_max=$(ethtool -l "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^Combined:/{print $2; exit}')
            if [ -n "$mq_max" ] && [ "$mq_max" -gt 1 ]; then
                mq_target="$cpu_cores"
                [ "$mq_target" -gt "$mq_max" ] && mq_target="$mq_max"
                if ethtool -L "$iface" combined "$mq_target" >/dev/null 2>&1; then
                    _log OK "    multi-queue: combined=$mq_target / max $mq_max"
                fi
            fi
        fi
        local f
        # RPS — RX softirq распределение
        for f in /sys/class/net/"$iface"/queues/rx-*/rps_cpus; do
            [ -e "$f" ] && sysfs_safe "$f" "$rps_mask"
        done
        # RFS — flow steering
        for f in /sys/class/net/"$iface"/queues/rx-*/rps_flow_cnt; do
            [ -e "$f" ] && sysfs_safe "$f" "${PRESET_RPS_FLOWS}"
        done
        # XPS — TX распределение. Каждой TX-очереди свой bitmask
        # с одним ядром из usable списка (минуя isolcpus).
        local txq_idx=0 cpu_pick
        for f in /sys/class/net/"$iface"/queues/tx-*/xps_cpus; do
            if [ -e "$f" ]; then
                cpu_pick="${usable_arr[$(( txq_idx % usable_n ))]:-0}"
                local one_cpu_mask
                one_cpu_mask=$(cpu_to_xps_mask "$cpu_pick")
                sysfs_safe "$f" "$one_cpu_mask"
                txq_idx=$(( txq_idx + 1 ))
            fi
        done

        # ВАЖНО: LRO выключаем — он ломает форвардинг.
        if [ "$DRY_RUN" != "1" ]; then
            ethtool -K "$iface" rx on tx on sg on tso on gso on gro on lro off >/dev/null 2>&1 || true

            # Ring buffers до железного максимума
            local ring_max_rx ring_max_tx
            ring_max_rx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^RX:/{print $2; exit}')
            ring_max_tx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^TX:/{print $2; exit}')
            if [ -n "$ring_max_rx" ] && [ -n "$ring_max_tx" ]; then
                ethtool -G "$iface" rx "$ring_max_rx" tx "$ring_max_tx" >/dev/null 2>&1 || true
            fi
            ethtool -C "$iface" adaptive-rx on adaptive-tx on >/dev/null 2>&1 || \
                ethtool -C "$iface" rx-usecs 8 tx-usecs 8 >/dev/null 2>&1 || true
        fi
    done
}

# Размазываем сетевые IRQ по ядрам. На многих VPS /proc/irq/*/smp_affinity_list
# не writable (provider запретил) — тогда мягко скипаем.
apply_irq_affinity() {
    local cpu_cores
    cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 2 ]; then
        _log INFO "${GRAY}[*] 1 CPU — IRQ affinity пропуск.${NC}"
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        _log INFO "${GRAY}[dry-run] IRQ affinity не трогаю${NC}"
        return 0
    fi
    # Гасим irqbalance, иначе он перетрёт наши настройки. В контейнерах он
    # обычно не запущен — просто скипаем ошибку.
    systemctl stop irqbalance 2>/dev/null || true
    systemctl disable irqbalance 2>/dev/null || true

    local usable_arr
    mapfile -t usable_arr < <(usable_cpus)
    local usable_n="${#usable_arr[@]}"
    [ "$usable_n" -eq 0 ] && usable_n="$cpu_cores"

    local iface irq_list irq cpu_idx=0 cpu_pick
    for iface in $(list_real_ifaces); do
        # IRQs принадлежащие интерфейсу — ищем в /proc/interrupts по
        # суффиксу с именем интерфейса (например, virtio0-input.0).
        irq_list=$(awk -v ifn="$iface" '$NF ~ ifn {gsub(":","",$1); print $1}' /proc/interrupts 2>/dev/null)
        for irq in $irq_list; do
            local affinity_file="/proc/irq/${irq}/smp_affinity_list"
            cpu_pick="${usable_arr[$(( cpu_idx % usable_n ))]:-0}"
            if [ -w "$affinity_file" ]; then
                # Пишем дважды: некоторые ядра возвращают EBUSY на первой записи
                # (особенно сразу после ethtool -L). Перепроверяем readback.
                local readback
                if echo "$cpu_pick" > "$affinity_file" 2>/dev/null; then
                    readback=$(cat "$affinity_file" 2>/dev/null)
                    if [ "$readback" = "$cpu_pick" ]; then
                        SYSFS_OK+=("irq#${irq}->cpu${cpu_pick}")
                    else
                        # Retry один раз
                        echo "$cpu_pick" > "$affinity_file" 2>/dev/null || true
                        readback=$(cat "$affinity_file" 2>/dev/null)
                        if [ "$readback" = "$cpu_pick" ]; then
                            SYSFS_OK+=("irq#${irq}->cpu${cpu_pick}(retry)")
                        else
                            SYSFS_SKIP+=("irq#${irq}:readback=$readback")
                        fi
                    fi
                else
                    SYSFS_SKIP+=("irq#${irq}:write-failed")
                fi
                cpu_idx=$(( cpu_idx + 1 ))
            else
                SYSFS_SKIP+=("irq#${irq}:no-write")
            fi
        done
    done
}

# CPU governor → performance. На share-VM часто залочено провайдером —
# скипаем без сбоя.
apply_cpu_governor() {
    [ "$DRY_RUN" = "1" ] && { _log INFO "${GRAY}[dry-run] CPU governor не трогаю${NC}"; return 0; }
    local f set=0
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        if [ -w "$f" ]; then
            echo performance > "$f" 2>/dev/null && set=1
        fi
    done
    if [ "$set" = "1" ]; then
        _log OK "${GREEN}[+] CPU governor → performance${NC}"
    else
        _log INFO "${GRAY}[*] CPU governor: на этой VPS не управляется (провайдер) — skip${NC}"
    fi
}

# Transparent Huge Pages → madvise (без latency spikes на прокси-нагрузках).
apply_thp() {
    [ "$DRY_RUN" = "1" ] && { _log INFO "${GRAY}[dry-run] THP не трогаю${NC}"; return 0; }
    if [ -w /sys/kernel/mm/transparent_hugepage/enabled ]; then
        if echo madvise > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null; then
            _log OK "${GREEN}[+] THP=madvise${NC}"
        fi
    fi
    if [ -w /sys/kernel/mm/transparent_hugepage/defrag ]; then
        echo madvise > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
    fi
}

# I/O scheduler: для NVMe — none, для SSD — mq-deadline. Плюс readahead.
apply_block_io() {
    [ "$DRY_RUN" = "1" ] && { _log INFO "${GRAY}[dry-run] block I/O не трогаю${NC}"; return 0; }
    local dev
    for dev in /sys/block/*; do
        local name="${dev##*/}"
        # Виртуальные / loop / zram пропускаем
        case "$name" in
            loop*|ram*|zram*|sr*|fd*|dm-*|md*) continue ;;
        esac
        local rotational
        rotational=$(cat "$dev/queue/rotational" 2>/dev/null || echo 1)
        local target="mq-deadline"
        # NVMe имена начинаются на nvme*; для них — none (multi-queue device)
        case "$name" in
            nvme*) target="none" ;;
        esac
        # HDD (rotational=1) → bfq если есть, иначе mq-deadline
        if [ "$rotational" = "1" ]; then target="mq-deadline"; fi
        if [ -w "$dev/queue/scheduler" ]; then
            local available
            available=$(cat "$dev/queue/scheduler" 2>/dev/null)
            if echo "$available" | grep -qw "$target"; then
                if echo "$target" > "$dev/queue/scheduler" 2>/dev/null; then
                    SYSFS_OK+=("$name:scheduler=$target")
                fi
            fi
        fi
        [ -w "$dev/queue/nr_requests" ] && \
            sysfs_safe "$dev/queue/nr_requests" 512
        [ -w "$dev/queue/read_ahead_kb" ] && \
            sysfs_safe "$dev/queue/read_ahead_kb" 128
    done
    # core_pattern → /dev/null: на закрытых cloud VM крах процесса не должен
    # съедать диск дампами.
    if [ -w /proc/sys/kernel/core_pattern ]; then
        sysctl_safe kernel.core_pattern "|/bin/false" || true
    fi
}

# Все sysctls — через probe-then-write. То, что ядро/гипервизор не приняли,
# не попадёт в persistent-конфиг. Это и есть главная фишка v7.0.
apply_sysctls() {
    local kvi
    kvi=$(kernel_version_int)

    # Базовые fs/kernel
    sysctl_safe fs.file-max 2000000
    sysctl_safe fs.nr_open 2000000
    sysctl_safe kernel.pid_max 4194304
    sysctl_safe fs.inotify.max_user_watches 524288
    sysctl_safe fs.inotify.max_user_instances 512
    sysctl_safe kernel.sched_autogroup_enabled 0
    sysctl_safe kernel.sched_migration_cost_ns 5000000

    # Подбираем congestion control из реально доступных
    local best_bbr="cubic"
    if has_cong_ctl bbr3; then best_bbr="bbr3"
    elif has_cong_ctl bbr2; then best_bbr="bbr2"
    elif has_cong_ctl bbr;  then best_bbr="bbr"
    fi

    local best_qdisc="fq_codel"
    if modprobe sch_cake 2>/dev/null; then best_qdisc="cake"
    elif modprobe sch_fq 2>/dev/null;   then best_qdisc="fq"
    fi
    [ "$best_bbr" != "cubic" ] && modprobe sch_fq 2>/dev/null && best_qdisc="fq"

    # Адаптивные буферы — масштабируются по RAM × множитель пресета.
    # Дополнительно учитываем реальную скорость сетевого линка через
    # ethtool: BDP = link_speed × ~150ms RTT. На 10G+ линке имеет смысл
    # поднять потолок до 512MB даже на VPS с малой RAM.
    local mem_mb buf_max=134217728
    mem_mb=$(free -m | awk '/Mem:/{print $2}')
    [ "$mem_mb" -ge 8192 ]  && buf_max=268435456
    [ "$mem_mb" -ge 16384 ] && buf_max=536870912

    local link_mbps=0 link_iface
    for link_iface in $(list_real_ifaces); do
        local s
        s=$(ethtool "$link_iface" 2>/dev/null | awk '/Speed:/{print $2}' | grep -oE '[0-9]+' | head -1)
        if [ -n "$s" ] && [ "$s" -gt "$link_mbps" ]; then
            link_mbps="$s"
        fi
    done
    if [ "$link_mbps" -ge 10000 ] && [ "$buf_max" -lt 268435456 ]; then
        buf_max=268435456  # 10G линк → минимум 256MB потолок
    fi
    if [ "$link_mbps" -ge 25000 ] && [ "$buf_max" -lt 536870912 ]; then
        buf_max=536870912  # 25G+ → 512MB потолок
    fi
    buf_max=$(( buf_max * PRESET_BUF_MULT ))

    # Networking core
    sysctl_safe net.core.default_qdisc "$best_qdisc"
    sysctl_safe net.ipv4.tcp_congestion_control "$best_bbr"
    sysctl_safe net.core.netdev_budget 600
    sysctl_safe net.core.netdev_budget_usecs 8000
    sysctl_safe net.core.netdev_max_backlog "$PRESET_NETDEV_BACKLOG"
    sysctl_safe net.core.somaxconn "$PRESET_SOMAXCONN"
    sysctl_safe net.core.busy_poll 50
    sysctl_safe net.core.busy_read 50
    sysctl_safe net.core.optmem_max 4194304
    sysctl_safe net.core.dev_weight 128
    sysctl_safe net.core.flow_limit_table_len 8192

    # NAPI defer (Linux 5.12+)
    if [ "$kvi" -ge 51200 ]; then
        sysctl_safe net.core.gro_flush_timeout 200000
        sysctl_safe net.core.napi_defer_hard_irqs 2
    fi

    # Buffers
    sysctl_safe net.core.rmem_max "$buf_max"
    sysctl_safe net.core.wmem_max "$buf_max"
    sysctl_safe net.core.rmem_default 2097152
    sysctl_safe net.core.wmem_default 2097152
    sysctl_safe net.ipv4.tcp_rmem "4096 2097152 $buf_max"
    sysctl_safe net.ipv4.tcp_wmem "4096 2097152 $buf_max"
    sysctl_safe net.ipv4.tcp_mem "786432 1048576 1572864"
    sysctl_safe net.ipv4.tcp_adv_win_scale -2
    sysctl_safe net.ipv4.tcp_moderate_rcvbuf 1
    sysctl_safe net.ipv4.tcp_notsent_lowat 131072

    # UDP — критично для QUIC/Reality/XHTTP
    sysctl_safe net.ipv4.udp_rmem_min 131072
    sysctl_safe net.ipv4.udp_wmem_min 131072
    sysctl_safe net.ipv4.udp_mem "786432 1048576 1572864"

    # TCP behavior
    sysctl_safe net.ipv4.tcp_mtu_probing 1
    sysctl_safe net.ipv4.tcp_window_scaling 1
    sysctl_safe net.ipv4.tcp_sack 1
    sysctl_safe net.ipv4.tcp_dsack 1
    sysctl_safe net.ipv4.tcp_fack 0
    sysctl_safe net.ipv4.tcp_timestamps 1
    sysctl_safe net.ipv4.tcp_no_metrics_save 1
    sysctl_safe net.ipv4.tcp_slow_start_after_idle 0
    sysctl_safe net.ipv4.tcp_tw_reuse 1
    sysctl_safe net.ipv4.tcp_max_tw_buckets "$PRESET_TCP_TW_BUCKETS"
    sysctl_safe net.ipv4.tcp_fin_timeout "$PRESET_TCP_FIN_TIMEOUT"
    sysctl_safe net.ipv4.tcp_keepalive_time "$PRESET_TCP_KEEPALIVE_TIME"
    sysctl_safe net.ipv4.tcp_keepalive_intvl 30
    sysctl_safe net.ipv4.tcp_keepalive_probes 5
    sysctl_safe net.ipv4.tcp_fastopen "$PRESET_TCP_FASTOPEN"
    sysctl_safe net.ipv4.tcp_max_syn_backlog 65535
    sysctl_safe net.ipv4.tcp_synack_retries 2
    sysctl_safe net.ipv4.tcp_syn_retries 3
    sysctl_safe net.ipv4.tcp_max_orphans "$PRESET_TCP_MAX_ORPHANS"
    sysctl_safe net.ipv4.tcp_orphan_retries 2
    sysctl_safe net.ipv4.tcp_min_snd_mss 536
    sysctl_safe net.ipv4.tcp_min_rtt_wlen 300
    sysctl_safe net.ipv4.tcp_pacing_ss_ratio "$PRESET_BBR_PACING_SS"
    sysctl_safe net.ipv4.tcp_pacing_ca_ratio "$PRESET_BBR_PACING_CA"
    sysctl_safe net.ipv4.tcp_collapse_max_bytes 6291456
    sysctl_safe net.ipv4.ip_local_port_range "$PRESET_PORT_RANGE"

    # Глубокая настройка TCP-стека (новое в v8.0):
    #  app_win=31 — максимум окна, отдаваемого приложению (важно для прокси),
    #  recovery=1 (RACK) — современный recovery-механизм по таймстампам,
    #  ecn=2 — пассивный ECN (отвечаем на ECN-флаги, но сами не запрашиваем),
    #  thin_linear_timeouts=1 — линейные ретраи на «тонких» соединениях,
    #  reordering — устойчивость к out-of-order пакетам в облачных сетях.
    sysctl_safe net.ipv4.tcp_app_win 31
    sysctl_safe net.ipv4.tcp_recovery 1
    sysctl_safe net.ipv4.tcp_ecn 2
    sysctl_safe net.ipv4.tcp_ecn_fallback 1
    sysctl_safe net.ipv4.tcp_thin_linear_timeouts 1
    sysctl_safe net.ipv4.tcp_reordering 6
    sysctl_safe net.ipv4.tcp_max_reordering 300
    sysctl_safe net.ipv4.tcp_early_retrans 3
    sysctl_safe net.ipv4.tcp_frto 2
    sysctl_safe net.ipv4.tcp_autocorking 0
    sysctl_safe net.ipv4.tcp_limit_output_bytes 1048576

    # Доводки под низкий пинг (новое в v8.1) — ТОЛЬКО то, чего ещё нет выше.
    # tcp_fin_timeout / tcp_keepalive_time / tcp_keepalive_intvl / tcp_keepalive_probes /
    # tcp_syn_retries / tcp_synack_retries / tcp_min_snd_mss / tcp_slow_start_after_idle
    # уже выставлены preset'ом или базовым блоком — их повторное переписывание перебило бы
    # значения из proxy/web preset'а (баг, исправлен в v8.1.1).
    #  - mtu_probing=1 + base_mss=1024 + probe_interval=600 + probe_threshold=8:
    #    лечит PMTU-чёрные дыры на туннелях/прокси (WireGuard/Reality/XHTTP).
    #  - workaround_signed_windows=1 — устраняет квирк старых клиентов.
    #  - tcp_retries2=8 — быстрее освобождаем мёртвые сокеты.
    #  - tcp_low_latency=1 — historic, безопасно: предпочитать latency throughput-у.
    #  - challenge_ack_limit=999 — без side-channel detection.
    #  - netdev_budget повышен для softirq на >1Gbps.
    sysctl_safe net.ipv4.tcp_mtu_probing 1
    sysctl_safe net.ipv4.tcp_base_mss 1024
    sysctl_safe net.ipv4.tcp_probe_interval 600
    sysctl_safe net.ipv4.tcp_probe_threshold 8
    sysctl_safe net.ipv4.tcp_workaround_signed_windows 1
    sysctl_safe net.ipv4.tcp_retries2 8
    sysctl_safe net.ipv4.tcp_low_latency 1
    sysctl_safe net.ipv4.tcp_challenge_ack_limit 999
    sysctl_safe net.ipv4.ip_no_pmtu_disc 0
    sysctl_safe net.core.netdev_budget 600
    sysctl_safe net.core.netdev_budget_usecs 8000
    sysctl_safe net.ipv4.tcp_invalid_ratelimit 500

    # MPTCP (Linux 5.6+)
    if [ "$kvi" -ge 50600 ]; then
        sysctl_safe net.mptcp.enabled 1
    fi

    # Маскировка стека: TTL=64 как у нативного Linux-десктопа.
    sysctl_safe net.ipv4.ip_default_ttl 64

    # Security / hygiene
    sysctl_safe net.ipv4.tcp_syncookies 1
    sysctl_safe net.ipv4.tcp_rfc1337 1
    sysctl_safe net.ipv4.conf.all.rp_filter 1
    sysctl_safe net.ipv4.conf.default.rp_filter 1
    sysctl_safe net.ipv4.conf.all.accept_redirects 0
    sysctl_safe net.ipv4.conf.default.accept_redirects 0
    sysctl_safe net.ipv4.conf.all.send_redirects 0
    sysctl_safe net.ipv4.conf.default.send_redirects 0
    sysctl_safe net.ipv4.conf.all.accept_source_route 0
    sysctl_safe net.ipv4.conf.default.accept_source_route 0
    sysctl_safe net.ipv4.icmp_echo_ignore_broadcasts 1
    sysctl_safe net.ipv6.conf.all.accept_redirects 0
    sysctl_safe net.ipv6.conf.default.accept_redirects 0

    # IPv6 mirror
    sysctl_safe net.ipv6.conf.all.disable_ipv6 0
    sysctl_safe net.ipv6.conf.default.disable_ipv6 0

    # conntrack — критический пункт для прокси-нагрузок. Модуль может быть
    # не загружен — пробуем поднять, sysctls появятся только после этого.
    modprobe nf_conntrack 2>/dev/null || true
    if kernel_supports_sysctl net.netfilter.nf_conntrack_max; then
        sysctl_safe net.netfilter.nf_conntrack_max "$PRESET_CONNTRACK_MAX"
        sysctl_safe net.netfilter.nf_conntrack_buckets "$PRESET_CONNTRACK_BUCKETS"
        sysctl_safe net.netfilter.nf_conntrack_tcp_timeout_established "$PRESET_CONNTRACK_TCP_TIMEOUT"
        sysctl_safe net.netfilter.nf_conntrack_tcp_timeout_time_wait 30
        sysctl_safe net.netfilter.nf_conntrack_tcp_timeout_close_wait 30
        sysctl_safe net.netfilter.nf_conntrack_tcp_timeout_fin_wait 30
        sysctl_safe net.netfilter.nf_conntrack_generic_timeout 120
    fi

    # VM / ZRAM tuning
    sysctl_safe vm.swappiness "$PRESET_SWAPPINESS"
    sysctl_safe vm.page-cluster 0
    sysctl_safe vm.vfs_cache_pressure 50
    sysctl_safe vm.dirty_background_ratio 3
    sysctl_safe vm.dirty_ratio 10
    sysctl_safe vm.dirty_writeback_centisecs 500
    sysctl_safe vm.dirty_expire_centisecs 1500
    sysctl_safe vm.min_free_kbytes 65536
    sysctl_safe vm.zone_reclaim_mode 0
    # Доводки v8.1:
    #  - max_map_count: высоко-thread'овые прокси (sing-box, gomod-сервисы)
    #    могут упираться в 65530 mmap'ов на процесс.
    #  - overcommit_memory=1: не отказываем в malloc()'е по «возможному» лимиту;
    #    Linux всё равно умеет OOM-кильнуть.
    #  - watermark_scale_factor=125: kswapd начинает чистить страницы раньше,
    #    меньше шансов попасть в direct reclaim (latency spike).
    #  - watermark_boost_factor=15000: меньше боусс'а — меньше «волн» компакции.
    #  - compaction_proactiveness=0: на VPS нет смысла греть CPU фоновой компакцией.
    #  - admin_reserve_kbytes: гарантирует ~16MB для root-shell даже при OOM.
    sysctl_safe vm.max_map_count 1048576
    sysctl_safe vm.overcommit_memory 1
    sysctl_safe vm.overcommit_ratio 100
    sysctl_safe vm.watermark_scale_factor 125
    sysctl_safe vm.watermark_boost_factor 15000
    sysctl_safe vm.compaction_proactiveness 0
    sysctl_safe vm.admin_reserve_kbytes 16384
    # Безопасные kernel/sched доводки.
    sysctl_safe kernel.sched_migration_cost_ns 5000000
    sysctl_safe kernel.sched_autogroup_enabled 0
    sysctl_safe kernel.numa_balancing 0
    sysctl_safe kernel.timer_migration 1
    # fs limits — на случай прокси с тысячами upstream'ов.
    sysctl_safe fs.file-max 2097152
    sysctl_safe fs.nr_open 2097152
    sysctl_safe fs.aio-max-nr 1048576

    APPLIED_BBR="$best_bbr"
    APPLIED_QDISC="$best_qdisc"
    APPLIED_BUF_MAX="$buf_max"
}

# Persistent unit: после ребута заново применяет RPS, RFS, XPS, LRO=off.
# Сами sysctls персистентны через /etc/sysctl.d/, а sysfs-настройки нет —
# поэтому именно их и восстанавливает этот юнит.
apply_persistent_units() {
    [ "$DRY_RUN" = "1" ] && return 0
    # Подставляем preset-зависимые значения и multi-queue target прямо в скрипт.
    local rps_flows="${PRESET_RPS_FLOWS:-4096}"
    cat > "$RPS_BOOT_SCRIPT" <<RPS_EOF
#!/bin/bash
# Auto-generated by vps_optimizer.sh — restores RPS/XPS/RFS/LRO/multi-queue after reboot.
set +e

build_cpu_mask() {
    local n=\$1
    [ "\$n" -le 0 ] && { echo 0; return; }
    local groups=\$(( (n + 31) / 32 ))
    local last_bits=\$(( n - (groups - 1) * 32 ))
    local first
    if [ "\$last_bits" -ge 32 ]; then
        first="ffffffff"
    else
        first=\$(printf '%x' \$(( (1 << last_bits) - 1 )))
    fi
    local rest="" i
    for ((i=1; i<groups; i++)); do rest=",ffffffff\${rest}"; done
    echo "\${first}\${rest}"
}

# CPU index → cpumask hex (kernel формат, comma-separated 32-bit chunks).
cpu_to_xps_mask() {
    local cpu="\${1:-0}"
    [ "\$cpu" -lt 0 ] && cpu=0
    local group=\$(( cpu / 32 ))
    local bit=\$(( cpu % 32 ))
    local val
    val=\$(printf '%x' \$(( 1 << bit )))
    if [ "\$group" -eq 0 ]; then
        echo "\$val"
    else
        local zeros="" i
        for ((i=0; i<group; i++)); do zeros+=",00000000"; done
        echo "\${val}\${zeros}"
    fi
}

# Парсим isolcpus= из cmdline и возвращаем список «usable» ядер.
usable_cpus() {
    local total iso= cmdline
    total=\$(nproc)
    cmdline=\$(cat /proc/cmdline 2>/dev/null)
    if [[ "\$cmdline" =~ isolcpus=([^[:space:]]+) ]]; then
        iso="\${BASH_REMATCH[1]}"
    fi
    declare -A bad
    if [ -n "\$iso" ]; then
        local part
        for part in \${iso//,/ }; do
            if [[ "\$part" =~ ^([0-9]+)-([0-9]+)\$ ]]; then
                local lo=\${BASH_REMATCH[1]} hi=\${BASH_REMATCH[2]} c
                for ((c=lo; c<=hi; c++)); do bad[\$c]=1; done
            elif [[ "\$part" =~ ^[0-9]+\$ ]]; then
                bad[\$part]=1
            fi
        done
    fi
    local c
    for ((c=0; c<total; c++)); do
        [ -z "\${bad[\$c]}" ] && echo "\$c"
    done
}

CORES=\$(nproc)
MASK=\$(build_cpu_mask "\$CORES")
mapfile -t USABLE < <(usable_cpus)
USABLE_N=\${#USABLE[@]}
[ "\$USABLE_N" -eq 0 ] && USABLE_N=1
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true

for IFACE in \$(ip -o link show | awk -F': ' '\$2 !~ /^(lo|virbr|docker|veth|wg|tun|tap|gre|ppp|br-|cilium|kube|cni)/ {print \$2}'); do
    # Multi-queue: восстанавливаем количество очередей до min(N_cpus, max_combined).
    MQ_MAX=\$(ethtool -l "\$IFACE" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^Combined:/{print \$2; exit}')
    if [ -n "\$MQ_MAX" ] && [ "\$MQ_MAX" -gt 1 ]; then
        MQ_TARGET="\$CORES"
        [ "\$MQ_TARGET" -gt "\$MQ_MAX" ] && MQ_TARGET="\$MQ_MAX"
        ethtool -L "\$IFACE" combined "\$MQ_TARGET" >/dev/null 2>&1 || true
    fi
    for f in /sys/class/net/"\$IFACE"/queues/rx-*/rps_cpus; do
        [ -e "\$f" ] && echo "\$MASK" > "\$f" 2>/dev/null || true
    done
    for f in /sys/class/net/"\$IFACE"/queues/rx-*/rps_flow_cnt; do
        [ -e "\$f" ] && echo $rps_flows > "\$f" 2>/dev/null || true
    done
    # XPS: каждой TX-очереди свой CPU из usable-списка (минуя isolcpus).
    txi=0
    for f in /sys/class/net/"\$IFACE"/queues/tx-*/xps_cpus; do
        if [ -e "\$f" ]; then
            cpu_pick="\${USABLE[\$(( txi % USABLE_N ))]:-0}"
            mask=\$(cpu_to_xps_mask "\$cpu_pick")
            echo "\$mask" > "\$f" 2>/dev/null || true
            txi=\$(( txi + 1 ))
        fi
    done
    ethtool -K "\$IFACE" lro off >/dev/null 2>&1 || true
done
RPS_EOF
    chmod +x "$RPS_BOOT_SCRIPT"
    cat > "$RPS_BOOT_SERVICE" <<EOF
[Unit]
Description=VPS RPS/RFS/XPS persistent tuning
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$RPS_BOOT_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now vps-rps.service >/dev/null 2>&1 || true
}

apply_limits() {
    [ "$DRY_RUN" = "1" ] && return 0
    cat > "$LIMITS_CONF" <<EOF
*       soft    nofile  $PRESET_NOFILE
*       hard    nofile  $PRESET_NOFILE
root    soft    nofile  $PRESET_NOFILE
root    hard    nofile  $PRESET_NOFILE
*       soft    nproc   unlimited
*       hard    nproc   unlimited
EOF
    mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
    cat > /etc/systemd/system.conf.d/99-vps-limits.conf <<EOF
[Manager]
DefaultLimitNOFILE=$PRESET_NOFILE
DefaultLimitNPROC=infinity
EOF
    cat > /etc/systemd/user.conf.d/99-vps-limits.conf <<EOF
[Manager]
DefaultLimitNOFILE=$PRESET_NOFILE
DefaultLimitNPROC=infinity
EOF
    systemctl daemon-reexec >/dev/null 2>&1 || true
}

# Шапка в persistent-файле sysctl. Туда уже накопилось всё, что
# реально применилось.
finalize_sysctl_conf() {
    [ "$DRY_RUN" = "1" ] && return 0
    if [ -f "$SYSCTL_CONF" ] && [ ! -f "$SYSCTL_BACKUP" ]; then
        cp "$SYSCTL_CONF" "$SYSCTL_BACKUP" 2>/dev/null || true
    fi
    {
        echo "# === VPS Optimizer v8.1.1 PHOENIX-Z+ ==="
        echo "# Generated $(date -u +%FT%TZ)  preset=$PRESET_NAME  virt=$VIRT  kernel=$(uname -r)"
        echo "# Только параметры, которые ядро/гипервизор реально приняли."
        cat "$SYSCTL_TMP" 2>/dev/null
    } > "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
}

# Сводка применённых/пропущенных настроек.
self_test() {
    local ok_count=${#SYSCTL_OK[@]}
    local skip_count=${#SYSCTL_SKIP[@]}
    local sysfs_ok=${#SYSFS_OK[@]}
    local sysfs_skip=${#SYSFS_SKIP[@]}

    [ "$QUIET" = "1" ] && return

    echo ""
    echo -e "${CYAN}${BOLD}=== Self-test ===${NC}"
    echo -e "  Preset:        ${BOLD}${PRESET_NAME}${NC}"
    echo -e "  Hypervisor:    ${BOLD}${VIRT}${NC}"
    echo -e "  Kernel:        $(uname -r)"
    echo -e "  Cores:         $(nproc)"
    echo -e "  RAM:           $(free -h | awk '/Mem:/{print $2}')"
    echo -e "  BBR:           ${GREEN}${APPLIED_BBR:-?}${NC}    qdisc: ${GREEN}${APPLIED_QDISC:-?}${NC}"
    echo -e "  buf_max:       ${APPLIED_BUF_MAX:-?} bytes"
    echo -e "  sysctl:        ${GREEN}${ok_count} OK${NC} / ${YELLOW}${skip_count} skipped${NC}"
    echo -e "  sysfs:         ${GREEN}${sysfs_ok} OK${NC} / ${YELLOW}${sysfs_skip} skipped${NC}"

    if [ "$skip_count" -gt 0 ]; then
        echo -e "  ${GRAY}Skipped sysctl (kernel/hypervisor restriction):${NC}"
        local s
        for s in "${SYSCTL_SKIP[@]}"; do
            echo -e "    ${GRAY}- $s${NC}"
        done | head -20
    fi
    echo ""
}

apply_optimizations() {
    [ "$DRY_RUN" = "1" ] && _log INFO "${YELLOW}[i] DRY-RUN: ничего не записывается на диск.${NC}"
    _log INFO "${YELLOW}[*] Глобальный тюнинг v8.1.1 PHOENIX-Z+...${NC}"

    VIRT=$(detect_virt)
    _log INFO "  Virt:    $VIRT"

    # Под OpenVZ половина sysctl запрещена — это нормально, всё пройдёт через
    # probe-then-write и просто залогируется как skipped.
    case "$VIRT" in
        openvz|lxc)
            _log INFO "${GRAY}[*] Контейнерный гипервизор ($VIRT) — часть тюнингов будет пропущена ядром, это ок.${NC}"
            ;;
    esac

    SYSCTL_OK=()
    SYSCTL_SKIP=()
    SYSFS_OK=()
    SYSFS_SKIP=()
    SYSCTL_TMP=$(mktemp /tmp/.vps_sysctl.XXXXXX)
    trap 'rm -f "$SYSCTL_TMP"' EXIT

    load_preset "$PRESET"
    apply_zram
    apply_iface_tuning
    apply_irq_affinity
    apply_cpu_governor
    apply_thp
    apply_block_io
    apply_sysctls
    apply_persistent_units
    apply_limits
    finalize_sysctl_conf

    self_test

    _log OK "${GREEN}[+] Phoenix-Z+ v8.1: BBR=${APPLIED_BBR}, qdisc=${APPLIED_QDISC}, preset=${PRESET_NAME}.${NC}"
    rm -f "$SYSCTL_TMP"; trap - EXIT

    [ "$QUIET" = "1" ] && return
    [ -t 0 ] && read -r -p "Нажмите Enter..."
}

#
# ----- Конфиг шумогенератора (рекомендованные значения) -----
#
# Что задаём в /etc/vps-noise.conf:
#   PROFILE             — какие домены крутить: ru | global | mixed
#   ENABLE_IOS_BURST    — фоновые «листания» iOS Safari (apple/icloud)
#   ENABLE_APNS         — TCP-keepalive на courier.push.apple.com:5223
#   ENABLE_EMAIL        — заходы на почту (Яндекс/Mail.ru/Max.ru)
#   ENABLE_NEWS         — новостные сайты + соцсети РФ
#   ENABLE_APT_PHANTOM  — фантомные APT-загрузки (пакеты + образы ОС)
#   *_INTERVAL_MIN/MAX  — диапазон случайной паузы между сессиями
#   APT_PHANTOM_PACKAGES — какие .deb качать и сразу выкидывать
#
# Рекомендованные значения подобраны так, чтобы суточная активность
# совпадала с поведением реального человека в РФ: ~10 проверок почты
# в день, ~25–40 заглядываний в новости, ~1–4 «обновления системы».
#
write_default_noise_conf() {
    cat > "$NOISE_CONF" <<'CONF_EOF'
# ============================================================
#  Конфиг VPS Noise Generator (Phoenix v6.1)
#  Все интервалы — в МИНУТАХ. Безопасно редактируется руками,
#  затем: systemctl restart vps-noise
# ============================================================

# Профиль доменов: ru | global | mixed
PROFILE="ru"

# --- Что включено ---
ENABLE_IOS_BURST=1        # фон iOS Safari (apple.com / icloud.com / ...)
ENABLE_APNS=1             # TCP-keepalive courier.push.apple.com:5223
ENABLE_EMAIL=1            # заходы в Яндекс.Почту / Mail.ru / Max.ru
ENABLE_NEWS=1             # новостные сайты + соцсети РФ
ENABLE_APT_PHANTOM=1      # фантомные APT-загрузки (libs + OS images)

# --- iOS бёрсты (рекомендованные: каждые 1–6 минут днём) ---
IOS_BURST_INTERVAL_MIN=1
IOS_BURST_INTERVAL_MAX=6

# --- Email-сессии (рекомендованные: каждые 45–180 минут) ---
# Реальный человек открывает почту 5–10 раз в день, по 1–3 минуты.
EMAIL_INTERVAL_MIN=45
EMAIL_INTERVAL_MAX=180

# --- News-сессии (рекомендованные: каждые 20–90 минут) ---
# Чтение новостей/соцсетей: ~25–40 коротких сессий за день.
NEWS_INTERVAL_MIN=20
NEWS_INTERVAL_MAX=90

# --- APT phantom (рекомендованные: каждые 6–24 часа = 360–1440 мин) ---
# unattended-upgrades в Ubuntu тикает раз в сутки, плюс пользователь
# часто руками вызывает apt update / apt install ~раз в несколько дней.
APT_PHANTOM_INTERVAL_MIN=360
APT_PHANTOM_INTERVAL_MAX=1440

# Сколько пакетов качать за один проход (1..N)
APT_PHANTOM_PKG_MIN=1
APT_PHANTOM_PKG_MAX=3

# Список «обычных» пакетов — они есть в стандартных репах Ubuntu,
# их регулярно тянут реальные админы. Можно дополнять.
APT_PHANTOM_PACKAGES="curl wget vim htop git tmux build-essential nginx \
ca-certificates net-tools iputils-ping rsync unzip zip jq python3-pip \
nodejs npm postgresql-client redis-tools mariadb-client tcpdump"

# Иногда (с этим шансом, 0..100) вместо обычной библиотеки качаем
# тяжёлый «образ ОС» — ядро, ubuntu-server, linux-headers. Это даёт
# редкие, но крупные всплески трафика, как при апгрейде дистрибутива.
APT_PHANTOM_OS_CHANCE=20
APT_PHANTOM_OS_PACKAGES="linux-image-generic linux-headers-generic \
ubuntu-server ubuntu-minimal cloud-init systemd"

# Если =1, вообще ничего не сохраняем на диск (всё уходит в /dev/null
# через --print-uris + curl). Если =0 — используется apt-get download
# во временный каталог с моментальным rm.
APT_PHANTOM_BLACKHOLE=1

# === Phantom library/archive downloads (новое в v8.0) ===
# Тянем релизы с GitHub / npm / PyPI / Maven / kernel.org / GNU ftp
# и т.п. → сразу в /dev/null. UA — curl/wget/pip/npm, без iOS.
ENABLE_LIB_PHANTOM=1
LIB_PHANTOM_INTERVAL_MIN=90      # минут (рекомендованно: 90)
LIB_PHANTOM_INTERVAL_MAX=360     # минут (рекомендованно: 360 = 6ч)
LIB_PHANTOM_BYTES_MAX=2097152    # cap на одно скачивание (2 MB)
LIB_PHANTOM_BURST_MIN=1
LIB_PHANTOM_BURST_MAX=3

# === Vacation mode (новое в v8.0) ===
# Раз в день кидаем кубик: с шансом VACATION_CHANCE_PCT уходим в тишину
# на VACATION_HOURS_MIN..MAX (как реально человек уехал на выходные).
ENABLE_VACATION=1
VACATION_CHANCE_PCT=7
VACATION_HOURS_MIN=6
VACATION_HOURS_MAX=72

# Глобальный rate-limit для curl (KB/s, диапазон min..max).
RATE_KB_MIN=500
RATE_KB_MAX=3500

# Окна суток (часы 0..23). Изменив их, можно подвинуть «график дня».
NIGHT_HOUR_FROM=1
NIGHT_HOUR_TO=6
PEAK_MORNING_FROM=7
PEAK_MORNING_TO=9
PEAK_EVENING_FROM=18
PEAK_EVENING_TO=23
CONF_EOF
}

# Показать текущий конфиг
show_noise_conf() {
    if [ -f "$NOISE_CONF" ]; then
        echo -e "${CYAN}--- $NOISE_CONF ---${NC}"
        cat "$NOISE_CONF"
    else
        echo -e "${YELLOW}[i] Конфиг ещё не создан.${NC}"
    fi
}

# Интерактивный ввод. Enter — оставить рекомендуемое значение.
prompt_custom_noise_conf() {
    [ -f "$NOISE_CONF" ] || write_default_noise_conf
    # shellcheck disable=SC1090
    source "$NOISE_CONF"

    echo -e "${CYAN}${BOLD}=== Кастомизация шумогенератора ===${NC}"
    echo -e "${YELLOW}Enter — оставить рекомендованное значение.${NC}"
    echo ""

    local v
    read -r -p "Профиль (ru/global/mixed) [${PROFILE}]: " v;             PROFILE="${v:-$PROFILE}"
    read -r -p "iOS-бёрсты (1=да/0=нет) [${ENABLE_IOS_BURST}]: " v;      ENABLE_IOS_BURST="${v:-$ENABLE_IOS_BURST}"
    read -r -p "APNs keepalive (1/0) [${ENABLE_APNS}]: " v;              ENABLE_APNS="${v:-$ENABLE_APNS}"
    read -r -p "Заходы в почту (1/0) [${ENABLE_EMAIL}]: " v;             ENABLE_EMAIL="${v:-$ENABLE_EMAIL}"
    read -r -p "Новости/соц.сети РФ (1/0) [${ENABLE_NEWS}]: " v;         ENABLE_NEWS="${v:-$ENABLE_NEWS}"
    read -r -p "APT-фантом (1/0) [${ENABLE_APT_PHANTOM}]: " v;           ENABLE_APT_PHANTOM="${v:-$ENABLE_APT_PHANTOM}"
    read -r -p "Library-фантом (GitHub/npm/PyPI/...) (1/0) [${ENABLE_LIB_PHANTOM:-1}]: " v
    ENABLE_LIB_PHANTOM="${v:-${ENABLE_LIB_PHANTOM:-1}}"
    read -r -p "Vacation mode (тишина 6–72ч раз в N дней) (1/0) [${ENABLE_VACATION:-1}]: " v
    ENABLE_VACATION="${v:-${ENABLE_VACATION:-1}}"

    echo ""
    echo -e "${CYAN}-- Email-сессии --${NC}"
    echo -e "${YELLOW}Рекомендуется: 45..180 минут (≈10 проверок в день).${NC}"
    read -r -p "EMAIL_INTERVAL_MIN [мин, ${EMAIL_INTERVAL_MIN}]: " v;    EMAIL_INTERVAL_MIN="${v:-$EMAIL_INTERVAL_MIN}"
    read -r -p "EMAIL_INTERVAL_MAX [мин, ${EMAIL_INTERVAL_MAX}]: " v;    EMAIL_INTERVAL_MAX="${v:-$EMAIL_INTERVAL_MAX}"

    echo ""
    echo -e "${CYAN}-- News-сессии --${NC}"
    echo -e "${YELLOW}Рекомендуется: 20..90 минут.${NC}"
    read -r -p "NEWS_INTERVAL_MIN [мин, ${NEWS_INTERVAL_MIN}]: " v;      NEWS_INTERVAL_MIN="${v:-$NEWS_INTERVAL_MIN}"
    read -r -p "NEWS_INTERVAL_MAX [мин, ${NEWS_INTERVAL_MAX}]: " v;      NEWS_INTERVAL_MAX="${v:-$NEWS_INTERVAL_MAX}"

    echo ""
    echo -e "${CYAN}-- APT-фантом --${NC}"
    echo -e "${YELLOW}Рекомендуется: 360..1440 минут (раз в 6–24 ч).${NC}"
    read -r -p "APT_PHANTOM_INTERVAL_MIN [мин, ${APT_PHANTOM_INTERVAL_MIN}]: " v
    APT_PHANTOM_INTERVAL_MIN="${v:-$APT_PHANTOM_INTERVAL_MIN}"
    read -r -p "APT_PHANTOM_INTERVAL_MAX [мин, ${APT_PHANTOM_INTERVAL_MAX}]: " v
    APT_PHANTOM_INTERVAL_MAX="${v:-$APT_PHANTOM_INTERVAL_MAX}"
    read -r -p "Шанс качнуть «образ ОС» вместо библиотеки (0..100) [${APT_PHANTOM_OS_CHANCE}]: " v
    APT_PHANTOM_OS_CHANCE="${v:-$APT_PHANTOM_OS_CHANCE}"
    read -r -p "Сразу в /dev/null без сохранения (1/0) [${APT_PHANTOM_BLACKHOLE}]: " v
    APT_PHANTOM_BLACKHOLE="${v:-$APT_PHANTOM_BLACKHOLE}"

    echo ""
    echo -e "${CYAN}-- Library-фантом (GitHub releases / npm / PyPI / kernel.org) --${NC}"
    echo -e "${YELLOW}Рекомендуется: 90..360 минут.${NC}"
    read -r -p "LIB_PHANTOM_INTERVAL_MIN [мин, ${LIB_PHANTOM_INTERVAL_MIN:-90}]: " v
    LIB_PHANTOM_INTERVAL_MIN="${v:-${LIB_PHANTOM_INTERVAL_MIN:-90}}"
    read -r -p "LIB_PHANTOM_INTERVAL_MAX [мин, ${LIB_PHANTOM_INTERVAL_MAX:-360}]: " v
    LIB_PHANTOM_INTERVAL_MAX="${v:-${LIB_PHANTOM_INTERVAL_MAX:-360}}"
    read -r -p "Cap на 1 скачивание [байт, ${LIB_PHANTOM_BYTES_MAX:-2097152}]: " v
    LIB_PHANTOM_BYTES_MAX="${v:-${LIB_PHANTOM_BYTES_MAX:-2097152}}"

    echo ""
    echo -e "${CYAN}-- Vacation mode --${NC}"
    echo -e "${YELLOW}Рекомендуется: 7% шанс/день, 6..72 часа.${NC}"
    read -r -p "VACATION_CHANCE_PCT [0..100, ${VACATION_CHANCE_PCT:-7}]: " v
    VACATION_CHANCE_PCT="${v:-${VACATION_CHANCE_PCT:-7}}"
    read -r -p "VACATION_HOURS_MIN [${VACATION_HOURS_MIN:-6}]: " v
    VACATION_HOURS_MIN="${v:-${VACATION_HOURS_MIN:-6}}"
    read -r -p "VACATION_HOURS_MAX [${VACATION_HOURS_MAX:-72}]: " v
    VACATION_HOURS_MAX="${v:-${VACATION_HOURS_MAX:-72}}"

    # Перезаписываем конфиг
    cat > "$NOISE_CONF" <<EOF
# vps-noise.conf (custom, $(date -u +%FT%TZ))
PROFILE="$PROFILE"

ENABLE_IOS_BURST=$ENABLE_IOS_BURST
ENABLE_APNS=$ENABLE_APNS
ENABLE_EMAIL=$ENABLE_EMAIL
ENABLE_NEWS=$ENABLE_NEWS
ENABLE_APT_PHANTOM=$ENABLE_APT_PHANTOM
ENABLE_LIB_PHANTOM=${ENABLE_LIB_PHANTOM:-1}
ENABLE_VACATION=${ENABLE_VACATION:-1}

LIB_PHANTOM_INTERVAL_MIN=${LIB_PHANTOM_INTERVAL_MIN:-90}
LIB_PHANTOM_INTERVAL_MAX=${LIB_PHANTOM_INTERVAL_MAX:-360}
LIB_PHANTOM_BYTES_MAX=${LIB_PHANTOM_BYTES_MAX:-2097152}
LIB_PHANTOM_BURST_MIN=${LIB_PHANTOM_BURST_MIN:-1}
LIB_PHANTOM_BURST_MAX=${LIB_PHANTOM_BURST_MAX:-3}

VACATION_CHANCE_PCT=${VACATION_CHANCE_PCT:-7}
VACATION_HOURS_MIN=${VACATION_HOURS_MIN:-6}
VACATION_HOURS_MAX=${VACATION_HOURS_MAX:-72}

IOS_BURST_INTERVAL_MIN=${IOS_BURST_INTERVAL_MIN}
IOS_BURST_INTERVAL_MAX=${IOS_BURST_INTERVAL_MAX}

EMAIL_INTERVAL_MIN=$EMAIL_INTERVAL_MIN
EMAIL_INTERVAL_MAX=$EMAIL_INTERVAL_MAX

NEWS_INTERVAL_MIN=$NEWS_INTERVAL_MIN
NEWS_INTERVAL_MAX=$NEWS_INTERVAL_MAX

APT_PHANTOM_INTERVAL_MIN=$APT_PHANTOM_INTERVAL_MIN
APT_PHANTOM_INTERVAL_MAX=$APT_PHANTOM_INTERVAL_MAX
APT_PHANTOM_PKG_MIN=${APT_PHANTOM_PKG_MIN}
APT_PHANTOM_PKG_MAX=${APT_PHANTOM_PKG_MAX}
APT_PHANTOM_PACKAGES="${APT_PHANTOM_PACKAGES}"
APT_PHANTOM_OS_CHANCE=$APT_PHANTOM_OS_CHANCE
APT_PHANTOM_OS_PACKAGES="${APT_PHANTOM_OS_PACKAGES}"
APT_PHANTOM_BLACKHOLE=$APT_PHANTOM_BLACKHOLE

RATE_KB_MIN=${RATE_KB_MIN}
RATE_KB_MAX=${RATE_KB_MAX}
NIGHT_HOUR_FROM=${NIGHT_HOUR_FROM}
NIGHT_HOUR_TO=${NIGHT_HOUR_TO}
PEAK_MORNING_FROM=${PEAK_MORNING_FROM}
PEAK_MORNING_TO=${PEAK_MORNING_TO}
PEAK_EVENING_FROM=${PEAK_EVENING_FROM}
PEAK_EVENING_TO=${PEAK_EVENING_TO}
EOF
    echo -e "${GREEN}[+] Конфиг сохранён в $NOISE_CONF${NC}"
}

manage_noise_generator() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}=== STEALTH NOISE GENERATOR (Phoenix v6.1) ===${NC}"
        local status
        if systemctl is-active --quiet vps-noise; then
            status="${GREEN}ВКЛЮЧЕН${NC}"
        else
            status="${RED}ОТКЛЮЧЕН${NC}"
        fi
        echo -e "Статус: $status"
        if [ -f "$NOISE_CONF" ]; then
            local p
            p=$(awk -F'"' '/^PROFILE=/{print $2}' "$NOISE_CONF")
            echo -e "Профиль: ${CYAN}${p:-?}${NC}    Конфиг: $NOISE_CONF"
        fi
        echo ""
        echo -e "  ${GREEN}[1]${NC} Запустить с ${BOLD}рекомендованными${NC} настройками"
        echo -e "  ${GREEN}[2]${NC} Запустить с ${BOLD}кастомными${NC} интервалами (мастер)"
        echo -e "  ${CYAN}[3]${NC} Открыть конфиг в редакторе (${EDITOR:-nano})"
        echo -e "  ${CYAN}[4]${NC} Показать текущий конфиг"
        echo -e "  ${YELLOW}[5]${NC} Перезапустить сервис (применить изменённый конфиг)"
        echo -e "  ${RED}[6]${NC} Выключить генератор"
        echo -e "  ${CYAN}[0]${NC} Назад"
        echo ""
        read -r -p "Выбор: " nchoice
        case $nchoice in
            1)
                write_default_noise_conf
                deploy_noise_generator
                echo -e "${GREEN}[+] Шум запущен с рекомендованными настройками.${NC}"
                sleep 2
                ;;
            2)
                prompt_custom_noise_conf
                deploy_noise_generator
                echo -e "${GREEN}[+] Шум запущен с кастомным конфигом.${NC}"
                sleep 2
                ;;
            3)
                [ -f "$NOISE_CONF" ] || write_default_noise_conf
                "${EDITOR:-nano}" "$NOISE_CONF"
                ;;
            4)
                clear
                show_noise_conf
                echo ""
                read -r -p "Нажмите Enter..."
                ;;
            5)
                systemctl restart vps-noise && echo -e "${GREEN}[+] Перезапущен.${NC}"
                sleep 1
                ;;
            6)
                systemctl stop vps-noise 2>/dev/null
                systemctl disable vps-noise 2>/dev/null
                sleep 1
                ;;
            0) return ;;
        esac
    done
}

# Раскладывает скрипт + systemd-юнит и (пере)запускает сервис.
deploy_noise_generator() {
    [ -f "$NOISE_CONF" ] || write_default_noise_conf
    cat > "$NOISE_GEN_SCRIPT" <<'NOISE_EOF'
#!/bin/bash
# vps-noise.sh — Phoenix v6.1 multi-profile noise generator.
# Полностью управляется через /etc/vps-noise.conf. Один процесс
# параллельно крутит несколько независимых сценариев активности:
#   - iOS Safari/CFNetwork бёрсты
#   - APNs keepalive
#   - Заходы в почту (Yandex/Mail.ru/Max.ru) — короткие сессии
#   - Чтение новостных сайтов и соцсетей РФ
#   - Фантомные APT-загрузки (.deb пакетов и тяжёлых ОС-образов)

set -u
umask 077

CONF="/etc/vps-noise.conf"
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"

# --- Дефолты на случай, если конфига нет / параметр забыли ---
PROFILE="${PROFILE:-ru}"
ENABLE_IOS_BURST="${ENABLE_IOS_BURST:-1}"
ENABLE_APNS="${ENABLE_APNS:-1}"
ENABLE_EMAIL="${ENABLE_EMAIL:-1}"
ENABLE_NEWS="${ENABLE_NEWS:-1}"
ENABLE_APT_PHANTOM="${ENABLE_APT_PHANTOM:-1}"

IOS_BURST_INTERVAL_MIN="${IOS_BURST_INTERVAL_MIN:-1}"
IOS_BURST_INTERVAL_MAX="${IOS_BURST_INTERVAL_MAX:-6}"
EMAIL_INTERVAL_MIN="${EMAIL_INTERVAL_MIN:-45}"
EMAIL_INTERVAL_MAX="${EMAIL_INTERVAL_MAX:-180}"
NEWS_INTERVAL_MIN="${NEWS_INTERVAL_MIN:-20}"
NEWS_INTERVAL_MAX="${NEWS_INTERVAL_MAX:-90}"
APT_PHANTOM_INTERVAL_MIN="${APT_PHANTOM_INTERVAL_MIN:-360}"
APT_PHANTOM_INTERVAL_MAX="${APT_PHANTOM_INTERVAL_MAX:-1440}"
APT_PHANTOM_PKG_MIN="${APT_PHANTOM_PKG_MIN:-1}"
APT_PHANTOM_PKG_MAX="${APT_PHANTOM_PKG_MAX:-3}"
APT_PHANTOM_OS_CHANCE="${APT_PHANTOM_OS_CHANCE:-20}"
APT_PHANTOM_BLACKHOLE="${APT_PHANTOM_BLACKHOLE:-1}"
APT_PHANTOM_PACKAGES="${APT_PHANTOM_PACKAGES:-curl wget vim htop git tmux nginx ca-certificates}"
APT_PHANTOM_OS_PACKAGES="${APT_PHANTOM_OS_PACKAGES:-linux-image-generic linux-headers-generic ubuntu-server}"

# ===== Phantom library downloads (новое в v8.0) =====
# Имитируем admin-host: периодически тянем релизы и tarball'ы
# из публичных package-репозиториев → /dev/null. Никаких мессенджеров.
ENABLE_LIB_PHANTOM="${ENABLE_LIB_PHANTOM:-1}"
LIB_PHANTOM_INTERVAL_MIN="${LIB_PHANTOM_INTERVAL_MIN:-90}"      # рекомендованно: 90 мин
LIB_PHANTOM_INTERVAL_MAX="${LIB_PHANTOM_INTERVAL_MAX:-360}"     # рекомендованно: 6 ч
LIB_PHANTOM_BYTES_MAX="${LIB_PHANTOM_BYTES_MAX:-2097152}"       # 2MB cap на одно скачивание
LIB_PHANTOM_BURST_MIN="${LIB_PHANTOM_BURST_MIN:-1}"
LIB_PHANTOM_BURST_MAX="${LIB_PHANTOM_BURST_MAX:-3}"

# ===== Vacation mode (новое в v8.0) =====
# Раз в день кидаем кубик: если выпало — уходим в тишину на N часов
# (как реально человек уехал в отпуск/лёг спать на выходные).
ENABLE_VACATION="${ENABLE_VACATION:-1}"
VACATION_CHANCE_PCT="${VACATION_CHANCE_PCT:-7}"   # 7% шанс начать «отпуск» в каждый новый день
VACATION_HOURS_MIN="${VACATION_HOURS_MIN:-6}"
VACATION_HOURS_MAX="${VACATION_HOURS_MAX:-72}"
RATE_KB_MIN="${RATE_KB_MIN:-500}"
RATE_KB_MAX="${RATE_KB_MAX:-3500}"
NIGHT_HOUR_FROM="${NIGHT_HOUR_FROM:-1}"
NIGHT_HOUR_TO="${NIGHT_HOUR_TO:-6}"
PEAK_MORNING_FROM="${PEAK_MORNING_FROM:-7}"
PEAK_MORNING_TO="${PEAK_MORNING_TO:-9}"
PEAK_EVENING_FROM="${PEAK_EVENING_FROM:-18}"
PEAK_EVENING_TO="${PEAK_EVENING_TO:-23}"

# ===== UA-пулы =====
UA_IOS=(
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
"AppleCoreMedia/1.0.0.22B83 (iPhone; U; CPU OS 18_1 like Mac OS X; en_us)"
"AppleCoreMedia/1.0.0.21F90 (iPhone; U; CPU OS 17_5 like Mac OS X; en_us)"
"itunesstored/1.0 iOS/18.1.1 model/iPhone16,2 hwp/t8130 build/22B91 (6; dt:264)"
"itunesstored/1.0 iOS/17.5.1 model/iPhone15,3 hwp/t8120 build/21F90 (6; dt:248)"
"com.apple.WebKit.Networking/8619.2.4.0.6 CFNetwork/1568.100.1 Darwin/24.1.0"
"com.apple.WebKit.Networking/8617.2.4.0.6 CFNetwork/1492.0.1 Darwin/23.3.0"
)

# Десктоп — для почты/новостей/соцсетей это естественнее, чем iOS Safari
UA_DESKTOP=(
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 YaBrowser/24.4.0.0 Safari/537.36"
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
)

UA_MOBILE_RU=(
"Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
"Mozilla/5.0 (Linux; arm_64; Android 13; RMX3771) AppleWebKit/537.36 (KHTML, like Gecko) YaBrowser/24.4.0 Mobile Safari/537.36"
)

# ===== URL-пулы =====
URLS_IOS=(
"https://www.apple.com/" "https://www.apple.com/iphone/"
"https://www.apple.com/shop/buy-iphone" "https://support.apple.com/"
"https://www.icloud.com/" "https://apps.apple.com/"
"https://itunes.apple.com/lookup?id=284910350"
"https://configuration.apple.com/configurations/internetservices/safari/ContentBlockerLists.plist.signed"
"https://gateway.icloud.com/" "https://mesu.apple.com/assets/"
"https://swcdn.apple.com/" "https://updates.cdn-apple.com/"
"https://is1-ssl.mzstatic.com/" "https://gs-loc.apple.com/"
"https://weatherkit.apple.com/" "https://news-events.apple.com/"
"https://gsa.apple.com/" "https://identity.apple.com/"
"https://api.weather.com/v3/" "https://gspe1-ssl.ls.apple.com/"
"https://gsas.apple.com/grandslam/" "https://xp.apple.com/report/2/"
"https://stocks-data-service.apple.com/" "https://itunes.apple.com/WebObjects/MZStore.woa/wa/viewMultiRoom"
"https://news-edge.apple.com/" "https://bagsvc.apple.com/" "https://buy.itunes.apple.com/"
)
URLS_CAPTIVE=(
"https://captive.apple.com/hotspot-detect.html"
"https://www.apple.com/library/test/success.html"
"https://gsp64-ssl.ls.apple.com/"
)

# РФ госпорталы / КИИ (новое в v8.1) — реальный iPhone владельца в РФ
# периодически открывает Госуслуги, ФНС, мос.ру и т.п. Никаких соцсетей,
# никаких мессенджеров. Все ссылки публичные и стабильные.
# shellcheck disable=SC2034
URLS_IOS_RU_GOV=(
"https://www.gosuslugi.ru/"
"https://lk.gosuslugi.ru/"
"https://login.gosuslugi.ru/"
"https://esia.gosuslugi.ru/"
"https://www.nalog.gov.ru/"
"https://lkfl2.nalog.ru/lkfl/login"
"https://www.fns.ru/"
"https://www.mos.ru/"
"https://www.mos.ru/services/"
"https://www.mos.ru/news/"
"https://pgu.mos.ru/"
"https://kremlin.ru/"
"https://government.ru/"
"https://www.gov.ru/"
"https://www.mvd.ru/"
"https://www.fsb.ru/"
"https://мвд.рф/"
"https://минцифры.рф/"
"https://digital.gov.ru/ru/"
"https://www.cbr.ru/"
"https://rkn.gov.ru/"
"https://sudrf.ru/"
"https://www.gov-murman.ru/"
"https://gisp.gov.ru/"
"https://nalog.ru/"
"https://минздрав.рф/"
"https://www.rosreestr.gov.ru/"
"https://лк.фнс.рф/"
"https://pos.gosuslugi.ru/og/"
"https://epgu.gosuslugi.ru/"
"https://www.pochta.ru/"
"https://www.pfrf.gov.ru/"
"https://sfr.gov.ru/"
)

# Yandex / Mail.ru / Max.ru — то, куда заходит реальный пользователь в РФ
# shellcheck disable=SC2034
URLS_EMAIL_YANDEX=(
"https://mail.yandex.ru/" "https://mail.yandex.ru/lite/"
"https://passport.yandex.ru/auth?origin=mail&from=mail"
"https://yandex.ru/" "https://disk.yandex.ru/"
"https://360.yandex.ru/mail/"
)
# shellcheck disable=SC2034
URLS_EMAIL_MAILRU=(
"https://mail.ru/" "https://e.mail.ru/inbox/" "https://e.mail.ru/login"
"https://account.mail.ru/login" "https://my.mail.ru/" "https://cloud.mail.ru/"
)
# shellcheck disable=SC2034
URLS_EMAIL_MAX=(
"https://max.ru/" "https://web.max.ru/" "https://max.ru/about"
)

URLS_NEWS_RU=(
"https://lenta.ru/" "https://ria.ru/" "https://www.rbc.ru/"
"https://tass.ru/" "https://www.kommersant.ru/" "https://www.vedomosti.ru/"
"https://www.gazeta.ru/" "https://rg.ru/" "https://iz.ru/"
"https://www.interfax.ru/" "https://www.kp.ru/"
"https://dzen.ru/news" "https://www.fontanka.ru/" "https://www.mk.ru/"
"https://meduza.io/"
)
URLS_SOCIAL_RU=(
"https://vk.com/" "https://ok.ru/" "https://dzen.ru/"
"https://www.wildberries.ru/" "https://www.ozon.ru/"
"https://www.avito.ru/" "https://hh.ru/"
)
URLS_SEARCH_RU=(
"https://yandex.ru/" "https://ya.ru/" "https://www.google.com/"
)

# ===== Phantom library/archive downloads (новое в v8.0) =====
# Правдоподобный admin-host: GitHub releases, npm/PyPI/Maven/CRAN метаданные
# и tarball'ы исходников kernel.org → /dev/null. URL'ы стабильные годами.
# shellcheck disable=SC2034
URLS_LIB_DOWNLOADS=(
"https://github.com/htop-dev/htop/archive/refs/tags/3.3.0.tar.gz"
"https://github.com/jqlang/jq/archive/refs/tags/jq-1.7.1.tar.gz"
"https://github.com/curl/curl/archive/refs/tags/curl-8_10_1.tar.gz"
"https://github.com/openssl/openssl/archive/refs/tags/openssl-3.4.0.tar.gz"
"https://github.com/postgres/postgres/archive/refs/tags/REL_17_2.tar.gz"
"https://github.com/redis/redis/archive/refs/tags/8.0.0.tar.gz"
"https://github.com/nginx/nginx/archive/refs/tags/release-1.27.3.tar.gz"
"https://github.com/grafana/grafana/archive/refs/tags/v11.4.0.tar.gz"
"https://github.com/prometheus/prometheus/archive/refs/tags/v3.0.1.tar.gz"
"https://github.com/python/cpython/archive/refs/tags/v3.13.1.tar.gz"
"https://github.com/torvalds/linux/archive/refs/tags/v6.12.tar.gz"
"https://github.com/golang/go/archive/refs/tags/go1.23.4.tar.gz"
"https://github.com/rust-lang/rust/archive/refs/tags/1.83.0.tar.gz"
"https://github.com/nodejs/node/archive/refs/tags/v22.12.0.tar.gz"
"https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-19.1.5.tar.gz"
"https://github.com/ffmpeg/FFmpeg/archive/refs/tags/n7.1.tar.gz"
"https://github.com/git/git/archive/refs/tags/v2.47.1.tar.gz"
"https://github.com/vim/vim/archive/refs/tags/v9.1.0900.tar.gz"
"https://github.com/neovim/neovim/archive/refs/tags/v0.10.3.tar.gz"
"https://github.com/tmux/tmux/archive/refs/tags/3.5a.tar.gz"
"https://registry.npmjs.org/express"
"https://registry.npmjs.org/react"
"https://registry.npmjs.org/typescript"
"https://registry.npmjs.org/webpack"
"https://registry.npmjs.org/lodash"
"https://pypi.org/simple/requests/"
"https://pypi.org/simple/numpy/"
"https://pypi.org/simple/django/"
"https://pypi.org/simple/flask/"
"https://pypi.org/simple/pandas/"
"https://files.pythonhosted.org/packages/source/r/requests/requests-2.32.3.tar.gz"
"https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar"
"https://repo1.maven.org/maven2/com/google/guava/guava/33.4.0-jre/guava-33.4.0-jre.jar"
"https://repo1.maven.org/maven2/org/springframework/spring-core/6.2.1/spring-core-6.2.1.jar"
"https://cran.r-project.org/src/contrib/PACKAGES"
"https://cran.r-project.org/src/contrib/dplyr_1.1.4.tar.gz"
"https://rubygems.org/gems/rails-7.2.2.gem"
"https://rubygems.org/gems/rake-13.2.1.gem"
"https://crates.io/api/v1/crates/serde/download"
"https://crates.io/api/v1/crates/tokio/download"
"https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.12.tar.xz"
"https://www.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.12"
"https://download.docker.com/linux/ubuntu/dists/noble/InRelease"
"https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz"
"https://archive.apache.org/dist/httpd/httpd-2.4.62.tar.bz2"
"https://archive.apache.org/dist/tomcat/tomcat-10/v10.1.34/bin/apache-tomcat-10.1.34.tar.gz"
"https://nodejs.org/dist/v22.12.0/node-v22.12.0-linux-x64.tar.xz"
"https://golang.org/dl/go1.23.4.linux-amd64.tar.gz"
"https://dl.google.com/go/go1.23.4.linux-amd64.tar.gz"
"https://www.openssl.org/source/openssl-3.4.0.tar.gz"
"https://ftp.gnu.org/gnu/coreutils/coreutils-9.5.tar.xz"
"https://ftp.gnu.org/gnu/binutils/binutils-2.43.tar.xz"
"https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz"
"https://ftp.postgresql.org/pub/source/v17.2/postgresql-17.2.tar.bz2"
)
# Реалистичные UA для admin/dev-host (не Safari iOS):
# shellcheck disable=SC2034
UA_LIBDL=(
"curl/8.10.1"
"curl/8.5.0"
"Wget/1.21.4"
"Wget/1.24.5"
"Debian APT-HTTP/1.3 (2.7.14) Ubuntu/24.04"
"Go-http-client/2.0"
"python-requests/2.32.3"
"pip/24.3.1 {\"ci\":null,\"cpu\":\"x86_64\",\"distro\":{\"name\":\"Ubuntu\",\"version\":\"24.04\"},\"implementation\":{\"name\":\"CPython\",\"version\":\"3.13.1\"}}"
"npm/10.9.2 node/v22.12.0 linux x64"
"Maven/3.9.9 (Java 21.0.5; Linux 6.8.0; amd64)"
)

# shellcheck disable=SC2034
URLS_GLOBAL=(
"https://www.bing.com/" "https://duckduckgo.com/"
"https://www.wikipedia.org/" "https://www.reddit.com/"
"https://news.ycombinator.com/" "https://www.bbc.com/"
"https://www.cnn.com/" "https://www.nytimes.com/"
)

ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
ACCEPT_LANG_RU="ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
ACCEPT_LANG_EN="en-US,en;q=0.9"
ACCEPT_ENC="gzip, deflate, br"

# ===== Бинарь curl =====
pick_curl() {
    if command -v curl_safari17_4 >/dev/null 2>&1; then echo curl_safari17_4
    elif command -v curl_safari16_5 >/dev/null 2>&1; then echo curl_safari16_5
    elif command -v curl-impersonate-safari >/dev/null 2>&1; then echo curl-impersonate-safari
    else echo curl
    fi
}
CURL_BIN=$(pick_curl)

COOKIE_JAR_DIR="/tmp/.vps_noise"
mkdir -p "$COOKIE_JAR_DIR"
chmod 700 "$COOKIE_JAR_DIR"

# Случайное число в диапазоне [a, b]
rrange() { echo $(( RANDOM % ($2 - $1 + 1) + $1 )); }

# Случайный rate-limit
rand_rate() { echo $(( RANDOM % (RATE_KB_MAX - RATE_KB_MIN + 1) + RATE_KB_MIN )); }

# ===== Один HTTP-запрос =====
# Аргументы: $1 — URL, $2 — UA-pool name (ios|desktop|mobile_ru), $3 — lang (ru|en), $4 — cookie tag
http_request() {
    local url="$1" ua_kind="${2:-ios}" lang="${3:-en}" tag="${4:-default}"
    local ua jar="$COOKIE_JAR_DIR/${tag}.jar"
    case "$ua_kind" in
        ios)        ua="${UA_IOS[$RANDOM % ${#UA_IOS[@]}]}" ;;
        desktop)    ua="${UA_DESKTOP[$RANDOM % ${#UA_DESKTOP[@]}]}" ;;
        mobile_ru)  ua="${UA_MOBILE_RU[$RANDOM % ${#UA_MOBILE_RU[@]}]}" ;;
        *)          ua="${UA_DESKTOP[$RANDOM % ${#UA_DESKTOP[@]}]}" ;;
    esac
    local accept_lang="$ACCEPT_LANG_EN"
    [ "$lang" = "ru" ] && accept_lang="$ACCEPT_LANG_RU"

    touch "$jar"

    local rate
    rate=$(rand_rate)
    local args=(
        -s -o /dev/null
        --max-time 25 --connect-timeout 8
        --tls-max 1.3 --tlsv1.2
        --compressed
        --cookie-jar "$jar" --cookie "$jar"
        -A "$ua"
        -H "Accept: $ACCEPT"
        -H "Accept-Language: $accept_lang"
        -H "Accept-Encoding: $ACCEPT_ENC"
        -H "Sec-Fetch-Dest: document"
        -H "Sec-Fetch-Mode: navigate"
        -H "Sec-Fetch-Site: none"
        -H "Upgrade-Insecure-Requests: 1"
        -H "Priority: u=0, i"
        --limit-rate "${rate}K"
    )
    if [ "$CURL_BIN" = "curl" ]; then
        if (( RANDOM % 3 == 0 )) && curl --help all 2>/dev/null | grep -q -- '--http3'; then
            args+=(--http3)
        else
            args+=(--http2)
        fi
    fi
    "$CURL_BIN" "${args[@]}" "$url" 2>/dev/null || true
}

# ===== APNs keepalive =====
apns_keepalive() {
    timeout 6 bash -c 'exec 3<>/dev/tcp/courier.push.apple.com/5223 && sleep 3' 2>/dev/null || true
}

# ===== iOS Safari бёрст =====
# Профиль реального iPhone-пользователя в РФ:
#   ~70%  Apple-домены (apple/icloud/mzstatic/...).
#   ~20%  Российские новости (lenta/ria/rbc/tass/...).
#   ~10%  Госпорталы РФ / КИИ (gosuslugi/mos.ru/nalog/...).
#   Никаких соцсетей, никаких мессенджеров.
ios_burst_pick() {
    local r=$(( RANDOM % 100 ))
    if (( r < 70 )); then
        echo "${URLS_IOS[$RANDOM % ${#URLS_IOS[@]}]}"
    elif (( r < 90 )); then
        echo "${URLS_NEWS_RU[$RANDOM % ${#URLS_NEWS_RU[@]}]}"
    else
        echo "${URLS_IOS_RU_GOV[$RANDOM % ${#URLS_IOS_RU_GOV[@]}]}"
    fi
}
ios_burst() {
    local n url
    n=$(rrange 3 8)
    # Первый запрос всегда Apple — это «открыли Safari».
    http_request "${URLS_IOS[$RANDOM % ${#URLS_IOS[@]}]}" ios en ios_session
    sleep "$(rrange 1 4)"
    local i
    for ((i=1; i<n; i++)); do
        url=$(ios_burst_pick)
        http_request "$url" ios en ios_session
        sleep "$(rrange 1 6)"
    done
    # Иногда — captive check
    if (( RANDOM % 5 == 0 )); then
        http_request "${URLS_CAPTIVE[$RANDOM % ${#URLS_CAPTIVE[@]}]}" ios en ios_captive
    fi
}

# ===== Email session =====
# Поведение: открыть главную почты → 2-5 переходов внутри → пауза.
# Чередуется между Яндексом, Mail.ru и Max.ru.
email_session() {
    local provider=$(( RANDOM % 3 ))
    local urls_var url n i
    case $provider in
        0) urls_var=URLS_EMAIL_YANDEX ;;
        1) urls_var=URLS_EMAIL_MAILRU ;;
        2) urls_var=URLS_EMAIL_MAX ;;
    esac
    # bash 4.3+ nameref — чисто и без eval
    local -n arr="$urls_var"
    n=$(rrange 2 5)
    for ((i=0; i<n; i++)); do
        url="${arr[$RANDOM % ${#arr[@]}]}"
        # 70% десктоп, 30% мобильный РФ-браузер
        if (( RANDOM % 10 < 7 )); then
            http_request "$url" desktop ru email
        else
            http_request "$url" mobile_ru ru email
        fi
        sleep "$(rrange 4 25)"
    done
}

# ===== News session =====
news_session() {
    local n url i
    # Стартовая точка — поисковик или прямой заход на новостник
    if (( RANDOM % 3 == 0 )); then
        http_request "${URLS_SEARCH_RU[$RANDOM % ${#URLS_SEARCH_RU[@]}]}" desktop ru news
        sleep "$(rrange 2 7)"
    fi
    n=$(rrange 3 9)
    for ((i=0; i<n; i++)); do
        if (( RANDOM % 4 == 0 )); then
            url="${URLS_SOCIAL_RU[$RANDOM % ${#URLS_SOCIAL_RU[@]}]}"
        else
            url="${URLS_NEWS_RU[$RANDOM % ${#URLS_NEWS_RU[@]}]}"
        fi
        if (( RANDOM % 10 < 6 )); then
            http_request "$url" desktop ru news
        else
            http_request "$url" mobile_ru ru news
        fi
        sleep "$(rrange 6 40)"
    done
}

# ===== APT phantom =====
# Настоящий unattended-upgrades регулярно делает `apt-get update` и
# подкачивает .deb. Мы делаем то же самое, но всё, что скачали —
# мгновенно отправляем в /dev/null. Системе не наносится никакого
# вреда: ни пакеты не ставятся, ни кэш не пухнет.
apt_phantom_run() {
    # apt-get update — это нормальная операция, она и так бы выполнялась.
    apt-get -qq -o Acquire::Languages=none update >/dev/null 2>&1 || true

    # APT_PHANTOM_PACKAGES — список через пробел, словосплит здесь намеренный
    # shellcheck disable=SC2206
    local pkgs=( $APT_PHANTOM_PACKAGES )
    # shellcheck disable=SC2206
    local os_pkgs=( $APT_PHANTOM_OS_PACKAGES )

    local n
    n=$(rrange "$APT_PHANTOM_PKG_MIN" "$APT_PHANTOM_PKG_MAX")

    local i pkg use_os tmpd
    for ((i=0; i<n; i++)); do
        use_os=0
        if (( RANDOM % 100 < APT_PHANTOM_OS_CHANCE )); then
            use_os=1
            pkg="${os_pkgs[$RANDOM % ${#os_pkgs[@]}]}"
        else
            pkg="${pkgs[$RANDOM % ${#pkgs[@]}]}"
        fi

        if [ "$APT_PHANTOM_BLACKHOLE" = "1" ]; then
            # Получаем список URI и тащим curl-ом прямо в /dev/null —
            # на диск ничего не пишется вообще.
            local uri_list
            uri_list=$(apt-get -y -qq --print-uris install --reinstall "$pkg" 2>/dev/null \
                       | awk -F"'" '/^'\''http/{print $2}')
            [ -z "$uri_list" ] && uri_list=$(apt-get -y -qq --print-uris download "$pkg" 2>/dev/null \
                       | awk -F"'" '/^'\''http/{print $2}')
            local u rate
            rate=$(rand_rate)
            for u in $uri_list; do
                curl -s -L --max-time 120 --connect-timeout 10 \
                    --limit-rate "${rate}K" \
                    -A "Debian APT-HTTP/1.3 (2.7.14) Ubuntu/24.04" \
                    "$u" -o /dev/null 2>/dev/null || true
            done
        else
            # Сохраняем .deb в tmpfs / временный каталог и сразу же rm.
            tmpd=$(mktemp -d /tmp/.apt_phantom.XXXXXX)
            ( cd "$tmpd" && apt-get -qq download "$pkg" >/dev/null 2>&1 || true )
            rm -rf "$tmpd"
        fi
        sleep "$(rrange 5 30)"

        # Ослабленный шум: «пользователь смотрит, что ставится» — реже
        # листает страницу пакета.
        if (( RANDOM % 3 == 0 )); then
            http_request "https://packages.ubuntu.com/noble/$pkg" desktop en apt
        fi
        # Иногда ОС-обновление сопровождается одним заходом на release-notes
        if [ "$use_os" = "1" ] && (( RANDOM % 2 == 0 )); then
            http_request "https://wiki.ubuntu.com/NobleNumbat/ReleaseNotes" desktop en apt
        fi
    done
}

# ===== Phantom library/archive downloads =====
# Тянет случайный URL (releases / npm / pypi / kernel.org / ...) до
# LIB_PHANTOM_BYTES_MAX и сразу в /dev/null. Скорость капается RATE_KB_MAX.
lib_phantom_run() {
    local burst i url ua rate
    burst=$(rrange "$LIB_PHANTOM_BURST_MIN" "$LIB_PHANTOM_BURST_MAX")
    for ((i=0; i<burst; i++)); do
        url="${URLS_LIB_DOWNLOADS[$RANDOM % ${#URLS_LIB_DOWNLOADS[@]}]}"
        ua="${UA_LIBDL[$RANDOM % ${#UA_LIBDL[@]}]}"
        rate=$(rand_rate)
        local CURL=(curl -s -o /dev/null -L \
            --max-filesize "$LIB_PHANTOM_BYTES_MAX" \
            --max-time 60 \
            --limit-rate "${rate}k" \
            --connect-timeout 10 \
            -H "Accept: */*" \
            -H "Accept-Encoding: gzip, deflate" \
            -A "$ua" \
            "$url")
        "${CURL[@]}" 2>/dev/null || true
        sleep "$(rrange 3 25)"
    done
}

# ===== Vacation mode =====
# Раз в день кидаем кубик; если выпало — пишем в state-файл время выхода
# из «отпуска». Все циклы в начале итерации проверяют этот файл и спят.
VACATION_FILE="/var/lib/vps-noise/vacation_until"
vacation_check_and_sleep() {
    [ "$ENABLE_VACATION" = "1" ] || return 0
    mkdir -p "$(dirname "$VACATION_FILE")"
    local now until
    now=$(date +%s)
    if [ -f "$VACATION_FILE" ]; then
        until=$(cat "$VACATION_FILE" 2>/dev/null || echo 0)
        if [ "$until" -gt "$now" ]; then
            sleep $(( until - now ))
            return 0
        else
            rm -f "$VACATION_FILE"
        fi
    fi
}
vacation_maybe_start() {
    [ "$ENABLE_VACATION" = "1" ] || return 0
    local marker
    marker="/var/lib/vps-noise/vacation_today_$(date +%Y%m%d)"
    [ -f "$marker" ] && return 0
    mkdir -p "$(dirname "$marker")"
    touch "$marker"
    if (( RANDOM % 100 < VACATION_CHANCE_PCT )); then
        local hours
        hours=$(rrange "$VACATION_HOURS_MIN" "$VACATION_HOURS_MAX")
        echo "$(( $(date +%s) + hours * 3600 ))" > "$VACATION_FILE"
    fi
}

# ===== Профиль времени суток (множитель пауз) =====
# Возвращает целочисленный множитель (в процентах) к базовому интервалу.
hour_factor() {
    local h
    h=$(date +%H); h=$((10#$h))
    if (( h >= NIGHT_HOUR_FROM && h <= NIGHT_HOUR_TO )); then
        echo 250                  # ночь — паузы в 2.5 раза длиннее
    elif (( h >= PEAK_MORNING_FROM && h <= PEAK_MORNING_TO )); then
        echo 60                   # утренний пик — короче
    elif (( h >= PEAK_EVENING_FROM && h <= PEAK_EVENING_TO )); then
        echo 70                   # вечерний пик
    else
        echo 100                  # день
    fi
}

# Случайная пауза в МИНУТАХ с учётом времени суток
sleep_minutes() {
    local mn=$1 mx=$2 base factor minutes
    base=$(rrange "$mn" "$mx")
    factor=$(hour_factor)
    minutes=$(( base * factor / 100 ))
    [ "$minutes" -lt 1 ] && minutes=1
    sleep "$((minutes * 60))"
}

# ===== Параллельные циклы =====
loop_ios() {
    while true; do
        vacation_maybe_start
        vacation_check_and_sleep
        ios_burst
        sleep_minutes "$IOS_BURST_INTERVAL_MIN" "$IOS_BURST_INTERVAL_MAX"
    done
}
loop_apns() {
    while true; do
        vacation_check_and_sleep
        apns_keepalive
        sleep "$(rrange 1500 2400)"   # ~25–40 мин
    done
}
loop_email() {
    while true; do
        sleep_minutes "$EMAIL_INTERVAL_MIN" "$EMAIL_INTERVAL_MAX"
        vacation_check_and_sleep
        email_session
    done
}
loop_news() {
    while true; do
        sleep_minutes "$NEWS_INTERVAL_MIN" "$NEWS_INTERVAL_MAX"
        vacation_check_and_sleep
        news_session
    done
}
loop_apt() {
    while true; do
        sleep_minutes "$APT_PHANTOM_INTERVAL_MIN" "$APT_PHANTOM_INTERVAL_MAX"
        vacation_maybe_start
        vacation_check_and_sleep
        apt_phantom_run
    done
}
loop_libdl() {
    while true; do
        sleep_minutes "$LIB_PHANTOM_INTERVAL_MIN" "$LIB_PHANTOM_INTERVAL_MAX"
        vacation_maybe_start
        vacation_check_and_sleep
        lib_phantom_run
    done
}

# Старт включённых модулей в фоне
PIDS=()
[ "$ENABLE_IOS_BURST"   = "1" ] && { loop_ios   & PIDS+=($!); }
[ "$ENABLE_APNS"        = "1" ] && { loop_apns  & PIDS+=($!); }
[ "$ENABLE_EMAIL"       = "1" ] && { loop_email & PIDS+=($!); }
[ "$ENABLE_NEWS"        = "1" ] && { loop_news  & PIDS+=($!); }
[ "$ENABLE_APT_PHANTOM" = "1" ] && command -v apt-get >/dev/null 2>&1 && { loop_apt & PIDS+=($!); }
[ "$ENABLE_LIB_PHANTOM" = "1" ] && { loop_libdl & PIDS+=($!); }

# Если ни один модуль не включён — спим, чтобы systemd не считал крах.
if [ "${#PIDS[@]}" -eq 0 ]; then
    while :; do sleep 3600; done
fi

# Если упадёт хоть один цикл — останавливаем сервис целиком, systemd
# его перезапустит (Restart=always), все циклы стартуют заново.
trap 'kill "${PIDS[@]}" 2>/dev/null; exit 0' TERM INT
wait -n
kill "${PIDS[@]}" 2>/dev/null || true
exit 1
NOISE_EOF
    chmod +x "$NOISE_GEN_SCRIPT"

    cat > "$NOISE_GEN_SERVICE" <<EOF
[Unit]
Description=VPS Phoenix Stealth Noise (iOS + RU human profile + APT phantom)
After=network-online.target dnsmasq.service
Wants=network-online.target

[Service]
ExecStart=$NOISE_GEN_SCRIPT
EnvironmentFile=-$NOISE_CONF
Restart=always
RestartSec=15
Nice=15
IOSchedulingClass=idle
CPUWeight=20
MemoryHigh=128M
MemoryMax=256M
StandardOutput=null
StandardError=null
PrivateTmp=yes
ProtectSystem=full
NoNewPrivileges=yes
StateDirectory=vps-noise
ReadWritePaths=/tmp /var/cache/apt /var/lib/apt /var/lib/vps-noise

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable vps-noise >/dev/null 2>&1
    systemctl restart vps-noise
}


manage_swap() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}=== УПРАВЛЕНИЕ ПОДКАЧКОЙ (SWAP & ZRAM) ===${NC}"
        echo -e "Текущая подкачка:"
        swapon --show || true
        echo ""
        echo -e "  ${GREEN}[1]${NC} Создать/Пересоздать SWAP-файл (в ГИГАБАЙТАХ)"
        echo -e "  ${YELLOW}[2]${NC} Активировать ZRAM (Сжатие в RAM)"
        echo -e "  ${RED}[3]${NC} Удалить SWAP-файл (/swapfile)"
        echo -e "  ${RED}[4]${NC} Отключить ZRAM (/dev/zram0)"
        echo -e "  ${CYAN}[0]${NC} Назад"
        echo ""
        read -r -p "Выбор: " schoice
        case $schoice in
            1)
                read -r -p "Введите желаемый размер SWAP в Гб (например, 2 или 4): " SWAP_GB
                if [[ ! "$SWAP_GB" =~ ^[0-9]+$ ]] || [ "$SWAP_GB" -le 0 ]; then
                    echo -e "${RED}[!] Ошибка: введите положительное целое число.${NC}"
                    sleep 2
                    continue
                fi

                echo -e "${YELLOW}[*] Подготовка файла подкачки на ${SWAP_GB}GB...${NC}"
                swapoff /swapfile 2>/dev/null || true
                rm -f /swapfile

                if ! fallocate -l "${SWAP_GB}G" /swapfile 2>/dev/null; then
                    echo -e "${YELLOW}[*] fallocate не удался, использую dd...${NC}"
                    dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_GB * 1024)) status=progress
                fi

                chmod 600 /swapfile
                mkswap /swapfile >/dev/null
                swapon /swapfile

                if ! grep -q "/swapfile" /etc/fstab; then
                    echo "/swapfile none swap sw 0 0" >> /etc/fstab
                fi
                echo -e "${GREEN}[+] SWAP-файл на ${SWAP_GB}GB активирован.${NC}"
                sleep 2
                ;;
            2)
                if modprobe zram 2>/dev/null; then
                    swapoff /dev/zram0 2>/dev/null || true
                    zramctl --reset /dev/zram0 2>/dev/null || true
                    local mem_total
                    mem_total=$(free -m | awk '/Mem:/{print $2}')
                    zramctl --find --size "$(( mem_total / 2 ))M" --algorithm zstd >/dev/null 2>&1 || \
                        zramctl --find --size "$(( mem_total / 2 ))M" --algorithm lz4 >/dev/null 2>&1
                    mkswap /dev/zram0 >/dev/null
                    swapon /dev/zram0 -p 100
                    echo -e "${GREEN}[+] ZRAM активирован.${NC}"
                else
                    echo -e "${RED}[!] ZRAM не поддерживается ядром.${NC}"
                fi
                sleep 2
                ;;
            3)
                echo -e "${YELLOW}[*] Удаление SWAP-файла...${NC}"
                swapoff /swapfile 2>/dev/null || true
                rm -f /swapfile
                sed -i '/\/swapfile/d' /etc/fstab
                echo -e "${GREEN}[+] SWAP-файл удалён.${NC}"
                sleep 2
                ;;
            4)
                echo -e "${YELLOW}[*] Отключение ZRAM...${NC}"
                swapoff /dev/zram0 2>/dev/null || true
                zramctl --reset /dev/zram0 2>/dev/null || true
                echo -e "${GREEN}[+] ZRAM отключён.${NC}"
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

experimental_menu() {
    clear
    echo -e "${CYAN}${BOLD}=== ЭКСПЕРИМЕНТАЛЬНЫЕ ОПЦИИ ===${NC}"
    echo "1. TCP Fast Open: $(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)"
    echo "2. ECN:           $(sysctl -n net.ipv4.tcp_ecn 2>/dev/null)"
    echo "3. busy_poll/read: $(sysctl -n net.core.busy_poll 2>/dev/null) / $(sysctl -n net.core.busy_read 2>/dev/null)"
    read -r -p "1/2/3 переключить, 0 назад: " e_choice
    case "$e_choice" in
        1) sysctl -w net.ipv4.tcp_fastopen=3 ;;
        2) sysctl -w net.ipv4.tcp_ecn=1 ;;
        3) sysctl -w net.core.busy_poll=50 net.core.busy_read=50 ;;
    esac
}

reset_all() {
    if [ "$DRY_RUN" = "1" ]; then
        echo -e "${YELLOW}[dry-run] reset_all: ничего не удаляю/не останавливаю.${NC}"
        return 0
    fi
    echo -e "${YELLOW}[*] Полный откат...${NC}"
    swapoff -a 2>/dev/null || true
    rm -f /swapfile
    sed -i '/\/swapfile/d' /etc/fstab
    zramctl --reset /dev/zram0 2>/dev/null || true
    # Восстанавливаем оригинальный DNS, если мы его ломали
    apply_dns local 2>/dev/null || true

    rm -f "$SYSCTL_CONF" "$LIMITS_CONF" "$EXP_CONF" "$NOISE_CONF" "$PRESET_FILE" \
          "$DNS_CONF" "$DNS_STATE" "$DNS_RESOLV_BACKUP" \
          /etc/dnsmasq.d/vps-speed.conf \
          /etc/systemd/system.conf.d/99-vps-limits.conf \
          /etc/systemd/user.conf.d/99-vps-limits.conf
    systemctl stop vps-noise vps-rps dnsmasq >/dev/null 2>&1 || true
    systemctl disable vps-noise vps-rps >/dev/null 2>&1 || true
    rm -f "$NOISE_GEN_SCRIPT" "$NOISE_GEN_SERVICE" "$RPS_BOOT_SCRIPT" "$RPS_BOOT_SERVICE"
    rm -rf /tmp/.vps_noise /var/lib/vps-noise
    systemctl daemon-reload >/dev/null 2>&1 || true
    sysctl --system >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] Сброс выполнен.${NC}"
    sleep 2
}

# ===================================================================
#  DNS configuration
# ===================================================================
# Пресеты публичных резолверов. По умолчанию никаких изменений не делаем
# (mode=local) — берётся то, что настроил провайдер.
DNS_PRESET_CLOUDFLARE="1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001"
DNS_PRESET_GOOGLE="8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844"
DNS_PRESET_YANDEX="77.88.8.8 77.88.8.1"
DNS_PRESET_QUAD9="9.9.9.9 149.112.112.112"
DNS_PRESET_ADGUARD="94.140.14.14 94.140.15.15"

# Server-name hostnames — нужны для DoT (RFC: IP#hostname для systemd-resolved)
# и DoH (URL). Без них strict TLS проверит только IP без SNI и упадёт.
DNS_SNI_CLOUDFLARE="cloudflare-dns.com"
DNS_SNI_GOOGLE="dns.google"
DNS_SNI_YANDEX="common.dot.dns.yandex.net"
DNS_SNI_QUAD9="dns.quad9.net"
DNS_SNI_ADGUARD="dns.adguard-dns.com"

# DoH stamps / URLs — для dnscrypt-proxy; URL'ы стандартные, проверены.
DNS_DOH_CLOUDFLARE="https://cloudflare-dns.com/dns-query"
DNS_DOH_GOOGLE="https://dns.google/dns-query"
DNS_DOH_YANDEX="https://common.dot.dns.yandex.net/dns-query"
DNS_DOH_QUAD9="https://dns.quad9.net/dns-query"
DNS_DOH_ADGUARD="https://dns.adguard-dns.com/dns-query"

# Возвращает SNI/host для DoT/DoH preset.
dns_preset_sni() {
    case "$1" in
        cloudflare) echo "$DNS_SNI_CLOUDFLARE" ;;
        google)     echo "$DNS_SNI_GOOGLE" ;;
        yandex)     echo "$DNS_SNI_YANDEX" ;;
        quad9)      echo "$DNS_SNI_QUAD9" ;;
        adguard)    echo "$DNS_SNI_ADGUARD" ;;
        *) echo "" ;;
    esac
}
dns_preset_doh_url() {
    case "$1" in
        cloudflare) echo "$DNS_DOH_CLOUDFLARE" ;;
        google)     echo "$DNS_DOH_GOOGLE" ;;
        yandex)     echo "$DNS_DOH_YANDEX" ;;
        quad9)      echo "$DNS_DOH_QUAD9" ;;
        adguard)    echo "$DNS_DOH_ADGUARD" ;;
        *) echo "" ;;
    esac
}

# Применяет выбранный DNS-режим. Сохраняет состояние в $DNS_STATE.
# Аргументы:  $1 = transport (plain|dot|doh) — по умолчанию plain.
#                  Если $1 — это preset (например 'cloudflare') или 'local'/'custom',
#                  считаем это backward-compat вызовом и transport=plain.
#             $2 = preset (local|cloudflare|google|yandex|quad9|adguard|custom)
#             $3 = (custom only) IP-адреса через пробел / DoH URL
apply_dns() {
    # Backward-compat: если первый аргумент — известный preset/local/custom, добавляем 'plain'.
    local transport="${1:-plain}"
    case "$transport" in
        plain|dot|doh) shift ;;
        local|cloudflare|google|yandex|quad9|adguard|custom|"")
            transport="plain"
            ;;
        *)
            _log WARN "${RED}[!] Неизвестный DNS transport: $transport${NC}"
            return 1
            ;;
    esac
    local mode="${1:-local}" servers=""
    if [ "$mode" = "local" ] || [ -z "$mode" ]; then
        # Полный сброс DNS — чем бы ни был transport.
        if [ "$DRY_RUN" = "1" ]; then
            _log INFO "${GRAY}[dry-run] DNS → local${NC}"
            return 0
        fi
        rm -f "$DNS_CONF" "$DNS_STATE"
        if [ -f "$DNS_RESOLV_BACKUP" ]; then
            cp -p "$DNS_RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null || true
        fi
        # Останавливаем DoH-прокси, если был запущен.
        systemctl disable --now dnscrypt-proxy 2>/dev/null || true
        systemctl restart systemd-resolved 2>/dev/null || true
        _log OK "${GREEN}[+] DNS режим: local (берётся конфигурация провайдера)${NC}"
        return 0
    fi
    case "$mode" in
        cloudflare) servers="$DNS_PRESET_CLOUDFLARE" ;;
        google)     servers="$DNS_PRESET_GOOGLE" ;;
        yandex)     servers="$DNS_PRESET_YANDEX" ;;
        quad9)      servers="$DNS_PRESET_QUAD9" ;;
        adguard)    servers="$DNS_PRESET_ADGUARD" ;;
        custom)     servers="${2:-}" ;;
        *)
            _log WARN "${RED}[!] Неизвестный DNS preset: $mode${NC}"
            return 1
            ;;
    esac

    if [ -z "$servers" ]; then
        _log WARN "${RED}[!] Список DNS-серверов пуст${NC}"
        return 1
    fi

    # Для plain/dot валидируем IP. Для doh при custom — может быть URL.
    if [ "$transport" != "doh" ] || [ "$mode" != "custom" ]; then
        local s
        for s in $servers; do
            if ! [[ "$s" =~ ^[0-9a-fA-F:.]+$ ]]; then
                _log WARN "${RED}[!] Невалидный DNS-сервер: $s${NC}"
                return 1
            fi
        done
    fi

    [ "$DRY_RUN" = "1" ] && {
        _log INFO "${GRAY}[dry-run] DNS → $transport/$mode ($servers)${NC}"
        return 0
    }

    case "$transport" in
        plain) dns_apply_plain "$mode" "$servers" ;;
        dot)   dns_apply_dot   "$mode" "$servers" ;;
        doh)   dns_apply_doh   "$mode" "$servers" ;;
    esac
    local rc=$?
    [ $rc -eq 0 ] && echo "$transport|$mode|$servers" > "$DNS_STATE"
    return $rc
}

# Plain DNS (UDP/TCP 53) через systemd-resolved drop-in или /etc/resolv.conf
dns_apply_plain() {
    local mode="$1" servers="$2"
    # Останавливаем dnscrypt-proxy, если был от предыдущего DoH.
    systemctl disable --now dnscrypt-proxy 2>/dev/null || true
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > "$DNS_CONF" <<EOF
# Auto-generated by vps_optimizer.sh — transport=plain preset=$mode
[Resolve]
DNS=$servers
DNSStubListener=yes
DNSSEC=allow-downgrade
DNSOverTLS=no
Cache=yes
EOF
        systemctl restart systemd-resolved 2>/dev/null
        _log OK "${GREEN}[+] DNS plain через systemd-resolved (preset=$mode):${NC}"
    else
        if [ ! -f "$DNS_RESOLV_BACKUP" ] && [ -e /etc/resolv.conf ]; then
            cp -p /etc/resolv.conf "$DNS_RESOLV_BACKUP" 2>/dev/null || true
        fi
        [ -L /etc/resolv.conf ] && rm -f /etc/resolv.conf
        {
            echo "# vps_optimizer.sh — transport=plain preset=$mode"
            local s
            for s in $servers; do echo "nameserver $s"; done
            echo "options edns0 trust-ad timeout:1 attempts:2"
        } > /etc/resolv.conf
        _log OK "${GREEN}[+] DNS plain через /etc/resolv.conf (preset=$mode):${NC}"
    fi
    _log OK "    $servers"
    return 0
}

# DoT (DNS-over-TLS, порт 853) — через systemd-resolved DNSOverTLS=yes (strict).
# Для valid TLS handshake server name указывается в формате IP#hostname.
dns_apply_dot() {
    local mode="$1" servers="$2"
    if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        _log WARN "${RED}[!] DoT требует systemd-resolved (на этой системе не активен)${NC}"
        _log INFO "${YELLOW}    fallback → plain${NC}"
        dns_apply_plain "$mode" "$servers"
        return $?
    fi
    systemctl disable --now dnscrypt-proxy 2>/dev/null || true
    local sni dns_line=""
    sni=$(dns_preset_sni "$mode")
    if [ "$mode" = "custom" ] || [ -z "$sni" ]; then
        # Для custom нет SNI — используем IP без hostname (TLS будет с проверкой по IP/SAN).
        dns_line="$servers"
    else
        local s line=""
        for s in $servers; do
            line+="${s}#${sni} "
        done
        dns_line="${line% }"
    fi
    mkdir -p /etc/systemd/resolved.conf.d
    cat > "$DNS_CONF" <<EOF
# Auto-generated by vps_optimizer.sh — transport=dot preset=$mode
[Resolve]
DNS=$dns_line
DNSStubListener=yes
DNSSEC=allow-downgrade
DNSOverTLS=yes
Cache=yes
EOF
    systemctl restart systemd-resolved 2>/dev/null
    _log OK "${GREEN}[+] DNS DoT (порт 853, strict TLS) preset=$mode:${NC}"
    _log OK "    $dns_line"
    return 0
}

# DoH (DNS-over-HTTPS, порт 443) через dnscrypt-proxy.
# dnscrypt-proxy ставим из apt (есть в noble), слушает 127.0.0.1:53,
# направляет запросы на DoH-эндпоинт. systemd-resolved должен быть отключён,
# либо мы пишем resolv.conf руками (точно укажет на наш прокси).
dns_apply_doh() {
    local mode="$1" servers="$2"
    if ! command -v dnscrypt-proxy >/dev/null 2>&1; then
        _log INFO "${YELLOW}[*] Устанавливаем dnscrypt-proxy (требуется для DoH)...${NC}"
        if ! apt-get update -qq >/dev/null 2>&1 || ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnscrypt-proxy >/dev/null 2>&1; then
            _log WARN "${RED}[!] Не удалось поставить dnscrypt-proxy. Fallback → DoT${NC}"
            dns_apply_dot "$mode" "$servers"
            return $?
        fi
    fi
    local doh_url
    if [ "$mode" = "custom" ]; then
        # Custom DoH — пользователь передал URL'ы (или IP, тогда не годится).
        local first
        first=$(echo "$servers" | awk '{print $1}')
        if [[ "$first" == https://* ]]; then
            doh_url="$first"
        else
            _log WARN "${RED}[!] Для DoH custom нужен URL (https://.../dns-query). Fallback → DoT${NC}"
            dns_apply_dot "$mode" "$servers"
            return $?
        fi
    else
        doh_url=$(dns_preset_doh_url "$mode")
    fi
    if [ -z "$doh_url" ]; then
        _log WARN "${RED}[!] Не нашли DoH URL для preset=$mode${NC}"
        return 1
    fi
    # Конфиг dnscrypt-proxy: server_names берётся из public-resolvers.md
    # (стандартный список dnscrypt/DoH-серверов), генерация stamp не нужна.
    mkdir -p /etc/dnscrypt-proxy
    local dnscp_server
    case "$mode" in
        cloudflare) dnscp_server="cloudflare" ;;
        google)     dnscp_server="google" ;;
        quad9)      dnscp_server="quad9-doh-ip4-port443-filter-pri" ;;
        adguard)    dnscp_server="adguard-dns-doh" ;;
        yandex)     dnscp_server="yandex" ;;
        *)          dnscp_server="cloudflare" ;;
    esac
    cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml <<EOF
# Auto-generated by vps_optimizer.sh — transport=doh preset=$mode
listen_addresses = ['127.0.0.1:53', '[::1]:53']
server_names = ['$dnscp_server']
ipv4_servers = true
ipv6_servers = true
doh_servers = true
require_dnssec = false
require_nolog = false
require_nofilter = false
cache = true
cache_size = 4096
cache_min_ttl = 600
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600
log_level = 2
[sources.public-resolvers]
  urls = ['https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md', 'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''
EOF
    mkdir -p /var/cache/dnscrypt-proxy
    chown -R _dnscrypt-proxy:_dnscrypt-proxy /var/cache/dnscrypt-proxy 2>/dev/null || true

    # Освобождаем :53 — выключаем resolved stub listener, перенаправляем resolved upstream на 127.0.0.1.
    # Альтернатива: полностью отключить resolved и писать /etc/resolv.conf напрямую.
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > "$DNS_CONF" <<EOF
# Auto-generated by vps_optimizer.sh — transport=doh
[Resolve]
DNS=127.0.0.1
DNSStubListener=no
DNSSEC=no
DNSOverTLS=no
Cache=no
EOF
        systemctl restart systemd-resolved 2>/dev/null
    fi
    if [ ! -f "$DNS_RESOLV_BACKUP" ] && [ -e /etc/resolv.conf ]; then
        cp -p /etc/resolv.conf "$DNS_RESOLV_BACKUP" 2>/dev/null || true
    fi
    [ -L /etc/resolv.conf ] && rm -f /etc/resolv.conf
    {
        echo "# vps_optimizer.sh — transport=doh (через dnscrypt-proxy на 127.0.0.1)"
        echo "nameserver 127.0.0.1"
        echo "options edns0 trust-ad timeout:1 attempts:2"
    } > /etc/resolv.conf

    systemctl enable --now dnscrypt-proxy 2>/dev/null || systemctl restart dnscrypt-proxy 2>/dev/null || true
    sleep 1
    if systemctl is-active --quiet dnscrypt-proxy 2>/dev/null; then
        _log OK "${GREEN}[+] DNS DoH (порт 443) preset=$mode → $dnscp_server${NC}"
        _log OK "    URL: $doh_url (через dnscrypt-proxy на 127.0.0.1)"
    else
        _log WARN "${RED}[!] dnscrypt-proxy не стартанул. Проверь: journalctl -u dnscrypt-proxy${NC}"
        return 1
    fi
    return 0
}

manage_dns_menu() {
    while true; do
        clear
        local cur_transport="plain" cur_mode="local" cur_servers=""
        if [ -f "$DNS_STATE" ]; then
            # Поддержка обеих схем: старая "mode|servers" и новая "transport|mode|servers".
            local raw
            raw=$(cat "$DNS_STATE")
            local n
            n=$(awk -F'|' '{print NF}' <<<"$raw")
            if [ "$n" = "3" ]; then
                cur_transport=$(cut -d'|' -f1 <<<"$raw")
                cur_mode=$(cut -d'|' -f2 <<<"$raw")
                cur_servers=$(cut -d'|' -f3- <<<"$raw")
            else
                cur_transport="plain"
                cur_mode=$(cut -d'|' -f1 <<<"$raw")
                cur_servers=$(cut -d'|' -f2- <<<"$raw")
            fi
        fi
        echo -e "${CYAN}${BOLD}=== DNS Configuration ===${NC}"
        echo -e "Текущий: ${BOLD}${cur_transport}${NC} / ${BOLD}${cur_mode}${NC}${cur_servers:+ (${cur_servers})}"
        echo ""
        echo -e "${YELLOW}1) Выбор транспорта (как DNS-запросы летят по сети):${NC}"
        echo -e "  ${GREEN}[1]${NC} ${BOLD}plain${NC}  — обычный DNS, порт 53/UDP+TCP (по умолчанию)"
        echo -e "  ${CYAN}[2]${NC}  ${BOLD}DoT${NC}    — DNS-over-TLS, порт 853 (через systemd-resolved strict)"
        echo -e "  ${CYAN}[3]${NC}  ${BOLD}DoH${NC}    — DNS-over-HTTPS, порт 443 (через dnscrypt-proxy, апт-ставится сам)"
        echo -e "  ${GREEN}[L]${NC}  Полный сброс к локальному (провайдерскому) DNS"
        echo -e "  ${GREEN}[0]${NC}  Назад"
        echo ""
        read -r -p "Транспорт: " t
        local transport=""
        case "$t" in
            1|p|plain|"") transport="plain" ;;
            2|t|dot|DoT)  transport="dot" ;;
            3|h|doh|DoH)  transport="doh" ;;
            L|l|local)    apply_dns plain local; read -r -p "Enter..."; continue ;;
            0) return ;;
            *) continue ;;
        esac
        echo ""
        echo -e "${YELLOW}2) Resolver:${NC}"
        echo -e "  ${CYAN}[1]${NC} Cloudflare"
        echo -e "  ${CYAN}[2]${NC} Google"
        echo -e "  ${CYAN}[3]${NC} Yandex"
        echo -e "  ${CYAN}[4]${NC} Quad9"
        echo -e "  ${CYAN}[5]${NC} AdGuard"
        echo -e "  ${YELLOW}[6]${NC} Custom (ввести IP/URL вручную)"
        echo -e "  ${GREEN}[0]${NC} Отмена"
        read -r -p "Resolver: " r
        local preset="" extra=""
        case "$r" in
            1) preset="cloudflare" ;;
            2) preset="google" ;;
            3) preset="yandex" ;;
            4) preset="quad9" ;;
            5) preset="adguard" ;;
            6)
                preset="custom"
                if [ "$transport" = "doh" ]; then
                    echo "DoH custom — введите URL (https://.../dns-query):"
                else
                    echo "Введите IP DNS-серверов через пробел (IPv4 или IPv6)."
                    echo "Пример: 1.1.1.1 8.8.8.8 2606:4700:4700::1111"
                fi
                read -r -p "> " extra
                ;;
            0|*) continue ;;
        esac
        apply_dns "$transport" "$preset" "$extra"
        read -r -p "Enter для продолжения..."
    done
}

# ===================================================================
#  Status dashboard
# ===================================================================
print_status_dashboard() {
    print_header
    local virt cores ram bbr qdisc
    virt=$(detect_virt)
    cores=$(nproc)
    ram=$(free -h | awk '/Mem:/{print $2}')
    bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)

    echo -e "${CYAN}${BOLD}=== СТАТУС VPS PHOENIX-Z+ ===${NC}"
    echo -e "  Hypervisor:    ${BOLD}$virt${NC}"
    echo -e "  Kernel:        $(uname -r)"
    echo -e "  Cores:         $cores"
    echo -e "  RAM:           $ram"
    echo -e "  Uptime:        $(uptime -p 2>/dev/null || uptime)"
    echo ""
    echo -e "${CYAN}--- Networking ---${NC}"
    echo -e "  Congestion:    ${GREEN}$bbr${NC}    Default qdisc: ${GREEN}$qdisc${NC}"
    echo -e "  rmem_max:      $(sysctl -n net.core.rmem_max 2>/dev/null || echo ?) bytes"
    echo -e "  wmem_max:      $(sysctl -n net.core.wmem_max 2>/dev/null || echo ?) bytes"
    echo -e "  somaxconn:     $(sysctl -n net.core.somaxconn 2>/dev/null || echo ?)"
    echo -e "  fastopen:      $(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo ?)"
    if [ -e /proc/sys/net/netfilter/nf_conntrack_count ]; then
        local cc cm
        cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
        cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
        echo -e "  conntrack:     $cc / $cm   ($(( cc * 100 / (cm > 0 ? cm : 1) ))% used)"
    fi

    echo ""
    echo -e "${CYAN}--- Memory / IO ---${NC}"
    echo -e "  swappiness:    $(sysctl -n vm.swappiness 2>/dev/null)"
    if command -v zramctl >/dev/null 2>&1; then
        local zline
        zline=$(zramctl --noheadings 2>/dev/null | head -n1)
        if [ -n "$zline" ]; then
            echo -e "  ZRAM:          ${GREEN}active${NC} ($zline)"
        else
            echo -e "  ZRAM:          ${GRAY}inactive${NC}"
        fi
    fi
    if [ -r /sys/kernel/mm/transparent_hugepage/enabled ]; then
        local thp
        thp=$(grep -oE '\[[a-z]+\]' /sys/kernel/mm/transparent_hugepage/enabled | tr -d '[]')
        echo -e "  THP:           $thp"
    fi
    echo -e "  open files:    $(awk '/^Max open files/{print $4}' /proc/self/limits 2>/dev/null || echo ?)"

    echo ""
    echo -e "${CYAN}--- Multi-core load ---${NC}"
    local iface
    for iface in $(list_real_ifaces); do
        local rx_q tx_q
        rx_q=$(find /sys/class/net/"$iface"/queues/ -maxdepth 1 -name 'rx-*' 2>/dev/null | wc -l)
        tx_q=$(find /sys/class/net/"$iface"/queues/ -maxdepth 1 -name 'tx-*' 2>/dev/null | wc -l)
        local lro
        lro=$(ethtool -k "$iface" 2>/dev/null | awk '/large-receive-offload/{print $2; exit}')
        local rps_set xps_set
        rps_set=$(cat /sys/class/net/"$iface"/queues/rx-0/rps_cpus 2>/dev/null)
        xps_set=$(cat /sys/class/net/"$iface"/queues/tx-0/xps_cpus 2>/dev/null)
        echo -e "  $iface: rx=$rx_q tx=$tx_q lro=${lro:-?} rps=${rps_set:-?} xps=${xps_set:-?}"
    done

    echo ""
    echo -e "${CYAN}--- Services ---${NC}"
    local svc
    for svc in vps-rps vps-noise; do
        if systemctl is-active --quiet "$svc"; then
            echo -e "  $svc: ${GREEN}active${NC}"
        else
            echo -e "  $svc: ${GRAY}inactive${NC}"
        fi
    done

    if [ -f "$PRESET_FILE" ]; then
        echo ""
        echo -e "  Preset:        ${BOLD}$(cat "$PRESET_FILE")${NC}"
    fi
    if [ -f "$DNS_STATE" ]; then
        local raw n dns_t dns_mode dns_servers
        raw=$(cat "$DNS_STATE")
        n=$(awk -F'|' '{print NF}' <<<"$raw")
        if [ "$n" = "3" ]; then
            dns_t=$(cut -d'|' -f1 <<<"$raw")
            dns_mode=$(cut -d'|' -f2 <<<"$raw")
            dns_servers=$(cut -d'|' -f3- <<<"$raw")
        else
            dns_t="plain"
            dns_mode=$(cut -d'|' -f1 <<<"$raw")
            dns_servers=$(cut -d'|' -f2- <<<"$raw")
        fi
        echo -e "  DNS:           ${BOLD}${dns_t}${NC} / ${BOLD}${dns_mode}${NC} (${dns_servers})"
    else
        echo -e "  DNS:           ${GRAY}local (provider default)${NC}"
    fi
    echo ""
}

# ===================================================================
#  Self-update / export / import
# ===================================================================
self_update() {
    local tmp
    tmp=$(mktemp /tmp/.vps_optimizer_new.XXXXXX)
    if curl -fsSL "$SELF_URL" -o "$tmp" && [ -s "$tmp" ]; then
        if bash -n "$tmp" 2>/dev/null; then
            chmod +x "$tmp"
            mv "$tmp" "$SELF_PATH"
            echo -e "${GREEN}[+] Скрипт обновлён до последней версии: $SELF_PATH${NC}"
        else
            rm -f "$tmp"
            echo -e "${RED}[!] Скачанная версия невалидна — обновление отменено.${NC}"
            return 1
        fi
    else
        rm -f "$tmp"
        echo -e "${RED}[!] Не удалось скачать $SELF_URL${NC}"
        return 1
    fi
}

export_config() {
    local target="${1:-/tmp/vps-phoenix-bundle.tar.gz}"
    local files=()
    [ -f "$SYSCTL_CONF" ]   && files+=("$SYSCTL_CONF")
    [ -f "$LIMITS_CONF" ]   && files+=("$LIMITS_CONF")
    [ -f "$NOISE_CONF" ]    && files+=("$NOISE_CONF")
    [ -f "$PRESET_FILE" ]   && files+=("$PRESET_FILE")
    [ -f "$DNS_CONF" ]      && files+=("$DNS_CONF")
    [ -f "$DNS_STATE" ]     && files+=("$DNS_STATE")
    [ -f "$RPS_BOOT_SCRIPT" ] && files+=("$RPS_BOOT_SCRIPT")
    [ -f "$RPS_BOOT_SERVICE" ] && files+=("$RPS_BOOT_SERVICE")
    [ -f "$NOISE_GEN_SCRIPT" ] && files+=("$NOISE_GEN_SCRIPT")
    [ -f "$NOISE_GEN_SERVICE" ] && files+=("$NOISE_GEN_SERVICE")
    [ -f /etc/systemd/system.conf.d/99-vps-limits.conf ] && \
        files+=("/etc/systemd/system.conf.d/99-vps-limits.conf")
    if [ "${#files[@]}" -eq 0 ]; then
        echo -e "${YELLOW}[!] Нечего экспортировать (apply ещё не запускался).${NC}"
        return 1
    fi
    tar czf "$target" "${files[@]}" 2>/dev/null
    echo -e "${GREEN}[+] Конфигурация выгружена в $target${NC}"
    echo -e "${GRAY}    Включено файлов: ${#files[@]}${NC}"
}

import_config() {
    local src="${1:?import path required}"
    if [ ! -f "$src" ]; then
        echo -e "${RED}[!] Нет файла: $src${NC}"; return 1
    fi
    tar xzf "$src" -C / 2>/dev/null && {
        echo -e "${GREEN}[+] Конфигурация импортирована.${NC}"
        sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart vps-rps vps-noise 2>/dev/null || true
        echo -e "${GREEN}[+] Сервисы перезапущены.${NC}"
    } || echo -e "${RED}[!] Распаковка не удалась.${NC}"
}

# ===================================================================
#  CLI parser
# ===================================================================
print_cli_help() {
    echo -e "${BOLD}vps_optimizer.sh${NC} — VPS Optimizer v8.1.1 PHOENIX-Z+"
    cat <<EOF

USAGE:
    vps_optimizer.sh                          # интерактивное меню
    vps_optimizer.sh <command> [options]      # CLI режим (без меню)

COMMANDS:
    install                  Установить компоненты Phoenix
    apply [--preset NAME]    Применить sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)
    status                   Показать дашборд состояния
    self-test                Перепроверить применённые настройки
    preset <name>            Сохранить пресет на будущие apply
    noise on|off|edit|status Управление шумогенератором
    dns ...                  Управление DNS:
                               dns                                   # статус
                               dns local                             # вернуть провайдер.
                               dns plain|dot|doh <preset>            # transport+resolver
                               dns plain|dot|doh custom <ip|url ...> # свои IP/URL
                             preset = cloudflare|google|yandex|quad9|adguard
                             plain = 53/UDP, dot = 853/TLS,
                             doh = 443/HTTPS (через dnscrypt-proxy, ставится автоматически)
    swap <gb>                Создать swap-файл указанного размера в ГБ
    benchmark                Замерить пинг до набора популярных endpoints
    reset                    Полный откат всех изменений
    export [path.tar.gz]     Выгрузить все конфиги в архив
    import <path.tar.gz>     Накатить выгруженные конфиги
    update                   Обновить скрипт до последней версии (GitHub main)
    help                     Эта справка

GLOBAL FLAGS:
    --dry-run                Только показать, что бы изменилось
    --quiet                  Минимум вывода (для скриптов/cron)
    --preset NAME            Использовать конкретный пресет (см. apply)

EXAMPLES:
    sudo ./vps_optimizer.sh apply --preset proxy
    sudo ./vps_optimizer.sh noise on
    sudo ./vps_optimizer.sh status
    sudo ./vps_optimizer.sh apply --dry-run
EOF
}

cli_dispatch() {
    local cmd="$1"; shift || true
    # Парсим глобальные флаги независимо от позиции
    local args=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --quiet|-q) QUIET=1 ;;
            --preset)  PRESET="$2"; shift ;;
            --preset=*) PRESET="${1#*=}" ;;
            *)         args+=("$1") ;;
        esac
        shift
    done

    case "$cmd" in
        install)        install_dependencies ;;
        apply|optimize) apply_optimizations ;;
        status)         print_status_dashboard ;;
        self-test)
            apply_optimizations >/dev/null
            self_test
            ;;
        preset)
            local name="${args[0]:-}"
            if [ -z "$name" ]; then
                echo -e "${RED}preset: укажи имя (balanced|proxy|web)${NC}"; exit 1
            fi
            echo "$name" > "$PRESET_FILE"
            echo -e "${GREEN}[+] Preset → $name (будет применён при следующем apply)${NC}"
            ;;
        noise)
            local sub="${args[0]:-status}"
            case "$sub" in
                on|start)
                    [ -f "$NOISE_CONF" ] || write_default_noise_conf
                    deploy_noise_generator
                    echo -e "${GREEN}[+] vps-noise.service запущен.${NC}"
                    ;;
                off|stop)
                    systemctl stop vps-noise 2>/dev/null
                    systemctl disable vps-noise 2>/dev/null
                    echo -e "${YELLOW}[*] vps-noise.service остановлен.${NC}"
                    ;;
                edit)
                    [ -f "$NOISE_CONF" ] || write_default_noise_conf
                    "${EDITOR:-nano}" "$NOISE_CONF"
                    ;;
                status|*)
                    if systemctl is-active --quiet vps-noise; then
                        echo -e "vps-noise: ${GREEN}active${NC}"
                    else
                        echo -e "vps-noise: ${GRAY}inactive${NC}"
                    fi
                    [ -f "$NOISE_CONF" ] && grep -E '^[A-Z_]+=' "$NOISE_CONF" | head -20
                    ;;
            esac
            ;;
        swap)
            local gb="${args[0]:-2}"
            # Простая неинтерактивная версия — создаёт swap-файл размера $gb GB.
            swapoff -a 2>/dev/null || true
            rm -f /swapfile
            fallocate -l "${gb}G" /swapfile
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null
            swapon /swapfile
            grep -q "^/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
            echo -e "${GREEN}[+] swap ${gb}G активен.${NC}"
            ;;
        benchmark) run_benchmark ;;
        reset)     reset_all ;;
        export)    export_config "${args[0]:-}" ;;
        import)
            if [ -z "${args[0]:-}" ]; then echo "import: укажи путь к архиву"; exit 1; fi
            import_config "${args[0]}"
            ;;
        dns)
            # Поддерживаются формы:
            #   dns                        — статус
            #   dns status                 — статус
            #   dns local                  — сброс к провайдерскому DNS
            #   dns <preset>               — backward-compat: plain + preset
            #   dns plain|dot|doh <preset>
            #   dns plain|dot|doh custom <ips/url...>
            local a0="${args[0]:-}"
            local a1="${args[1]:-}"
            case "$a0" in
                ""|status)
                    if [ -f "$DNS_STATE" ]; then
                        echo "DNS: $(cat "$DNS_STATE")"
                    else
                        echo "DNS: local (не управляется)"
                    fi
                    ;;
                local)
                    apply_dns plain local
                    ;;
                plain|dot|doh)
                    if [ -z "$a1" ]; then
                        echo -e "${RED}dns $a0: укажи resolver (cloudflare|google|yandex|quad9|adguard|custom)${NC}"
                        exit 1
                    fi
                    if [ "$a1" = "custom" ]; then
                        local rest
                        rest="${args[*]:2}"
                        apply_dns "$a0" custom "$rest"
                    else
                        apply_dns "$a0" "$a1"
                    fi
                    ;;
                cloudflare|google|yandex|quad9|adguard)
                    apply_dns plain "$a0"
                    ;;
                custom)
                    local shift_args
                    shift_args="${args[*]:1}"
                    apply_dns plain custom "$shift_args"
                    ;;
                *)
                    echo -e "${RED}dns: использование:${NC}"
                    echo "  dns                              # статус"
                    echo "  dns local                        # вернуть провайдерский DNS"
                    echo "  dns plain|dot|doh <preset>       # plain/DoT/DoH"
                    echo "  dns plain|dot|doh custom <args>  # custom IP-адреса (или URL для DoH)"
                    echo "  preset = cloudflare|google|yandex|quad9|adguard"
                    exit 1
                    ;;
            esac
            ;;
        update)    self_update ;;
        help|-h|--help) print_cli_help ;;
        *)         echo -e "${RED}Неизвестная команда: $cmd${NC}"; print_cli_help; exit 1 ;;
    esac
}

# ===================================================================
#  Интерактивное меню
# ===================================================================
manage_presets_menu() {
    clear
    echo -e "${CYAN}${BOLD}=== Профили оптимизации ===${NC}"
    local cur="balanced"
    [ -f "$PRESET_FILE" ] && cur=$(cat "$PRESET_FILE")
    echo -e "Текущий: ${BOLD}$cur${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} balanced — универсальный (по умолчанию)"
    echo -e "  ${GREEN}[2]${NC} proxy    — xray/sing-box/wg, агрессивные буферы и conntrack"
    echo -e "  ${GREEN}[3]${NC} web      — nginx/apache, security-акценты"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) echo balanced > "$PRESET_FILE"; echo -e "${GREEN}[+] preset=balanced${NC}"; sleep 1 ;;
        2) echo proxy    > "$PRESET_FILE"; echo -e "${GREEN}[+] preset=proxy${NC}"; sleep 1 ;;
        3) echo web      > "$PRESET_FILE"; echo -e "${GREEN}[+] preset=web${NC}"; sleep 1 ;;
        0) ;;
    esac
}

main_menu() {
    while true; do
        print_header
        local cur_preset="balanced"
        [ -f "$PRESET_FILE" ] && cur_preset=$(cat "$PRESET_FILE")
        echo -e "Profile: ${CYAN}${BOLD}$cur_preset${NC}    Hypervisor: $(detect_virt)"
        echo ""
        echo -e "Выберите действие:"
        echo -e "  ${GREEN}[1]${NC} Подготовка: компоненты Phoenix-X"
        echo -e "  ${CYAN}[2]${NC} ${BOLD}Применить v8.1${NC} (multi-queue / XPS / MTU-probe / DoT/DoH / VM-tune / iOS-RU)"
        echo -e "  ${CYAN}[3]${NC} Stealth: генератор шума (iOS + RU email/news + APT phantom)"
        echo -e "  ${CYAN}[4]${NC} Подкачка: SWAP & ZRAM"
        echo -e "  ${CYAN}[5]${NC} Бенчмарк (пинг до популярных endpoints)"
        echo -e "  ${CYAN}[6]${NC} Status дашборд"
        echo -e "  ${CYAN}[7]${NC} Профиль оптимизации (balanced / proxy / web)"
        echo -e "  ${CYAN}[11]${NC} DNS (local / Cloudflare / Yandex / Quad9 / Custom...)"
        echo -e "  ${YELLOW}[9]${NC} Self-update из GitHub"
        echo -e "  ${YELLOW}[10]${NC} Export / Import конфигов"
        echo -e "  ${YELLOW}[12]${NC} Экспериментально: TFO / ECN / busy_poll"
        echo -e "  ${RED}[8]${NC} Полный откат всех изменений"
        echo -e "  ${GREEN}[0]${NC} Выход"
        echo ""
        read -r -p "Ваш выбор: " choice
        case $choice in
            1)  install_dependencies ;;
            2)  apply_optimizations ;;
            3)  manage_noise_generator ;;
            4)  manage_swap ;;
            5)  run_benchmark ;;
            6)  print_status_dashboard; read -r -p "Нажмите Enter..." ;;
            7)  manage_presets_menu ;;
            9)  self_update; read -r -p "Нажмите Enter..." ;;
            10) clear
                echo -e "${CYAN}--- Export / Import ---${NC}"
                echo "  [1] Export → /tmp/vps-phoenix-bundle.tar.gz"
                echo "  [2] Import от пути"
                read -r -p "Выбор: " exi
                case "$exi" in
                    1) export_config; read -r -p "Enter..." ;;
                    2) read -r -p "Путь к архиву: " p; import_config "$p"; read -r -p "Enter..." ;;
                esac
                ;;
            11) manage_dns_menu ;;
            12) experimental_menu ;;
            8)  reset_all ;;
            0)  exit 0 ;;
            *)  echo -e "${RED}[!] Неверный выбор.${NC}"; sleep 1 ;;
        esac
    done
}

# ===================================================================
#  Точка входа: CLI или интерактивное меню
# ===================================================================

if [ $# -gt 0 ]; then
    # help/status — без проверки root, остальные команды требуют sudo
    case "$1" in
        help|-h|--help) print_cli_help; exit 0 ;;
        status)
            print_status_dashboard
            exit 0
            ;;
    esac
    check_root
    cli_dispatch "$@"
    exit $?
fi
check_root
main_menu
