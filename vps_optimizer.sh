#!/bin/bash

# ==============================================================================
# VPS Global Optimization Script (v5.0 SUPERNOVA - ULTIMATE EDITION)
# ==============================================================================

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

SYSCTL_CONF="/etc/sysctl.d/99-vps-optimizer.conf"
LIMITS_CONF="/etc/security/limits.d/99-vps-limits.conf"
NOISE_GEN_SCRIPT="/usr/local/bin/vps_noise_gen.sh"
NOISE_GEN_SERVICE="/etc/systemd/system/vps-noise.service"
EXP_CONF="/etc/sysctl.d/99-vps-experimental.conf"

function print_header {
    clear
    echo -e "${MAGENTA}${BOLD}"
    echo "================================================================="
    echo "     ULTRA VPS ACCELERATOR v5.0 (SUPERNOVA EDITION)            "
    echo "================================================================="
    echo -e "   ZRAM, RPS/RFS Tuning, DNS Cache, Stealth Noise, Benchmark"
    echo -e "=================================================================${NC}"
    echo ""
}

function check_root {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Запустите от имени root.${NC}"; exit 1
    fi
}

function install_dependencies {
    echo -e "${YELLOW}[*] Установка компонентов Supernova...${NC}"
    apt-get update -y
    apt-get install -y curl ethtool iproute2 dnsmasq util-linux bc zram-tools > /dev/null 2>&1
    
    # Настройка Dnsmasq
    echo -e "listen-address=127.0.0.1\ncache-size=10000\nno-resolv\nserver=1.1.1.1\nserver=8.8.8.8" > /etc/dnsmasq.d/vps-speed.conf
    systemctl restart dnsmasq > /dev/null 2>&1
    
    echo -e "${GREEN}[+] Базовые компоненты установлены.${NC}"
    sleep 1
}

function run_benchmark {
    clear
    echo -e "${CYAN}${BOLD}=== ТЕСТ ЗАДЕРЖКИ (BENCHMARK) ===${NC}"
    echo "Замеряем средний пинг до глобальных узлов..."
    
    TARGETS=("www.google.com" "www.apple.com" "1.1.1.1")
    for TARGET in "${TARGETS[@]}"; do
        echo -n "Тест $TARGET: "
        PING_RES=$(ping -c 4 "$TARGET" | awk -F '/' 'END {if ($5) print $5; else print ""}')
        if [ -z "$PING_RES" ]; then
            echo -e "${RED}ОШИБКА (Timeout)${NC}"
        else
            echo -e "${GREEN}${PING_RES} ms${NC}"
        fi
    done
    echo ""
    read -p "Нажмите Enter..."
}

function apply_optimizations {
    echo -e "${YELLOW}[*] Глобальный тюнинг системы v5.0...${NC}"

    # 1. Многоядерная обработка пакетов (RPS/RFS)
    INTERFACES=$(ip -o link show | awk -F': ' '$2 !~ /lo|virbr|docker|veth/ {print $2}')
    CPU_CORES=$(nproc)
    # Маска для всех ядер (напр. f для 4 ядер)
    RPS_MASK=$(printf '%x' $(( (1 << CPU_CORES) - 1 )))
    
    for IFACE in $INTERFACES; do
        echo -e "${YELLOW}[*] RPS/RFS тюнинг: $IFACE (Маска: $RPS_MASK)${NC}"
        # Включаем RPS на всех очередях
        for file in /sys/class/net/$IFACE/queues/rx-*/rps_cpus; do echo "$RPS_MASK" > "$file" 2>/dev/null; done
        # Включаем RFS
        echo "32768" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null
        for file in /sys/class/net/$IFACE/queues/rx-*/rps_flow_cnt; do echo "4096" > "$file" 2>/dev/null; done
        
        # Аппаратное ускорение
        ethtool -K $IFACE rx on tx on sg on tso on gso on gro on lro on > /dev/null 2>&1 || true
        ethtool -C $IFACE rx-usecs 1 tx-usecs 1 > /dev/null 2>&1 || true
    done

    # 2. ZRAM Настройка (Сжатая память) - Авто-настройка
    if modprobe zram 2>/dev/null; then
        echo -e "${YELLOW}[*] Активация ZRAM акселератора...${NC}"
        swapoff /dev/zram0 2>/dev/null
        zramctl --reset /dev/zram0 2>/dev/null
        
        MEM_TOTAL=$(free -m | awk '/Mem:/{print $2}')
        ZRAM_SIZE=$(( MEM_TOTAL / 2 ))
        if [ "$ZRAM_SIZE" -lt 128 ]; then ZRAM_SIZE=128; fi
        
        zramctl --find --size "${ZRAM_SIZE}M" --algorithm zstd
        mkswap /dev/zram0 > /dev/null 2>&1
        swapon /dev/zram0 -p 100
        echo -e "${GREEN}[+] ZRAM активен (${ZRAM_SIZE}MB, zstd).${NC}"
    else
        echo -e "${RED}[!] ZRAM не поддерживается ядром.${NC}"
    fi

    # 3. Sysctl Ultra Tuning
    BEST_BBR="bbr"
    if modprobe tcp_bbr3 2>/dev/null || grep -q "bbr3" /proc/modules; then BEST_BBR="bbr3";
    elif modprobe tcp_bbr2 2>/dev/null || grep -q "bbr2" /proc/modules; then BEST_BBR="bbr2"; fi

    cat <<EOF > $SYSCTL_CONF
# --- Supernova Performance ---
fs.file-max = 2000000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = $BEST_BBR
net.core.netdev_budget = 600
net.core.netdev_max_backlog = 500000
net.core.rps_sock_flow_entries = 32768
net.ipv4.tcp_mtu_probing = 2

# --- Buffers (3 Gbps Optimized) ---
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.ipv4.tcp_rmem = 4096 2097152 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# --- Stealth & Latency ---
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.ip_default_ttl = 64
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fastopen = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# --- Security ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_fin_timeout = 10
EOF
    
    sysctl -p $SYSCTL_CONF > /dev/null 2>&1
    echo -e "${GREEN}[+] Система v5.0 полностью оптимизирована.${NC}"
    echo ""
    read -p "Нажмите Enter..."
}

function manage_noise_generator {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}=== STEALTH NOISE GENERATOR (Day/Night) ===${NC}"
        systemctl is-active --quiet vps-noise && STATUS="${GREEN}ВКЛЮЧЕН${NC}" || STATUS="${RED}ОТКЛЮЧЕН${NC}"
        echo -e "Статус: $STATUS"
        echo ""
        echo -e "  ${GREEN}[1]${NC} Включить генератор (Изоляция CPU + Сон)"
        echo -e "  ${RED}[2]${NC} Выключить генератор"
        echo -e "  ${CYAN}[0]${NC} Назад"
        echo ""
        read -p "Выбор: " nchoice
        case $nchoice in
            1)
                cat <<'EOF' > $NOISE_GEN_SCRIPT
#!/bin/bash
HTTPS_URLS=("https://www.apple.com" "https://www.icloud.com" "https://apps.apple.com" "https://yandex.ru")
UA="Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
while true; do
    HOUR=$(date +%H)
    if (( HOUR >= 2 && HOUR <= 7 )); then
        curl -s -k -A "$UA" "https://www.apple.com/robots.txt" -o /dev/null
        sleep $((RANDOM % 1200 + 1200))
    else
        S_LIMIT=$((RANDOM % 4 + 2))
        for ((i=1; i<=S_LIMIT; i++)); do
            URL="${HTTPS_URLS[$RANDOM % ${#HTTPS_URLS[@]}]}"
            curl -s -k --http2 -A "$UA" --limit-rate "$((RANDOM % 2000 + 1000))K" "$URL" -o /dev/null
            sleep $((RANDOM % 10 + 2))
        done
        sleep $((RANDOM % 300 + 60))
    fi
done
EOF
                chmod +x $NOISE_GEN_SCRIPT
                LAST_CORE=$(( $(nproc) - 1 ))
                cat <<EOF > $NOISE_GEN_SERVICE
[Unit]
Description=VPS iOS Supernova Noise
After=network.target
[Service]
ExecStart=$NOISE_GEN_SCRIPT
Restart=always
CPUAffinity=$LAST_CORE
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload && systemctl enable vps-noise && systemctl start vps-noise
                echo -e "${GREEN}[+] Шум запущен на ядре $LAST_CORE.${NC}"; sleep 1 ;;
            2) systemctl stop vps-noise && systemctl disable vps-noise; sleep 1 ;;
            0) return ;;
        esac
    done
}

function manage_swap {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}=== УПРАВЛЕНИЕ ПОДКАЧКОЙ (SWAP & ZRAM) ===${NC}"
        echo -e "Текущая подкачка:"
        swapon --show
        echo ""
        echo -e "  ${GREEN}[1]${NC} Создать/Пересоздать SWAP-файл (в ГИГАБАЙТАХ)"
        echo -e "  ${YELLOW}[2]${NC} Активировать ZRAM (Сжатие в RAM)"
        echo -e "  ${RED}[3]${NC} Удалить SWAP-файл (/swapfile)"
        echo -e "  ${RED}[4]${NC} Отключить ZRAM (/dev/zram0)"
        echo -e "  ${CYAN}[0]${NC} Назад"
        echo ""
        read -p "Выбор: " schoice
        case $schoice in
            1)
                read -p "Введите желаемый размер SWAP в Гб (например, 2 или 4): " SWAP_GB
                if [[ ! "$SWAP_GB" =~ ^[0-9]+$ ]] || [ "$SWAP_GB" -le 0 ]; then
                    echo -e "${RED}[!] Ошибка: введите положительное целое число.${NC}"; sleep 2; continue
                fi
                
                echo -e "${YELLOW}[*] Подготовка файла подкачки на ${SWAP_GB}GB...${NC}"
                swapoff /swapfile 2>/dev/null
                rm -f /swapfile
                
                # Создание файла (fallocate быстрее, dd надежнее)
                if ! fallocate -l ${SWAP_GB}G /swapfile 2>/dev/null; then
                    echo -e "${YELLOW}[*] fallocate не удался, использую dd (это может занять время)...${NC}"
                    dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_GB * 1024)) status=progress
                fi
                
                chmod 600 /swapfile
                mkswap /swapfile > /dev/null
                swapon /swapfile
                
                # Автозагрузка
                if ! grep -q "/swapfile" /etc/fstab; then
                    echo "/swapfile none swap sw 0 0" >> /etc/fstab
                fi
                echo -e "${GREEN}[+] SWAP-файл на ${SWAP_GB}GB успешно активирован.${NC}"; sleep 2 ;;
            2)
                if modprobe zram 2>/dev/null; then
                    swapoff /dev/zram0 2>/dev/null
                    zramctl --reset /dev/zram0 2>/dev/null
                    MEM_TOTAL=$(free -m | awk '/Mem:/{print $2}')
                    zramctl --find --size $(( MEM_TOTAL / 2 ))M --algorithm zstd
                    mkswap /dev/zram0 > /dev/null
                    swapon /dev/zram0 -p 100
                    echo -e "${GREEN}[+] ZRAM активирован.${NC}"
                else
                    echo -e "${RED}[!] ZRAM не поддерживается вашим ядром.${NC}"
                fi
                sleep 2 ;;
            3)
                echo -e "${YELLOW}[*] Удаление SWAP-файла...${NC}"
                swapoff /swapfile 2>/dev/null
                rm -f /swapfile
                sed -i '/\/swapfile/d' /etc/fstab
                echo -e "${GREEN}[+] SWAP-файл удален из системы.${NC}"; sleep 2 ;;
            4)
                echo -e "${YELLOW}[*] Отключение ZRAM...${NC}"
                swapoff /dev/zram0 2>/dev/null
                zramctl --reset /dev/zram0 2>/dev/null
                echo -e "${GREEN}[+] ZRAM отключен.${NC}"; sleep 2 ;;
            0) return ;;
        esac
    done
}

function main_menu {
    while true; do
        print_header
        echo -e "Выберите действие:"
        echo -e "  ${GREEN}[1]${NC} Подготовка: Компоненты Supernova"
        echo -e "  ${CYAN}[2]${NC} УСКОРЕНИЕ: v5.0 (ZRAM + RPS + Stealth)"
        echo -e "  ${CYAN}[3]${NC} Stealth: Генератор шума"
        echo -e "  ${CYAN}[4]${NC} Подкачка: SWAP & ZRAM (Ручная настройка)"
        echo -e "  ${CYAN}[5]${NC} Тест: Запустить Бенчмарк (Пинг)"
        echo -e "  ${RED}[12]${NC} Экспериментально: TFO / ECN"
        echo -e "  ${RED}[8]${NC} Полный откат всех изменений"
        echo -e "  ${GREEN}[0]${NC} Выход"
        echo ""
        read -p "Ваш выбор: " choice
        case $choice in
            1) install_dependencies ;;
            2) apply_optimizations ;;
            3) manage_noise_generator ;;
            4) manage_swap ;;
            5) run_benchmark ;;
            12)
                clear
                echo -e "1. TFO: $(sysctl -n net.ipv4.tcp_fastopen)\n2. ECN: $(sysctl -n net.ipv4.tcp_ecn)"
                read -p "1 или 2 для переключения (0 назад): " e_choice
                [[ "$e_choice" == "1" ]] && sysctl -w net.ipv4.tcp_fastopen=3
                [[ "$e_choice" == "2" ]] && sysctl -w net.ipv4.tcp_ecn=1
                ;;
            8)
                swapoff -a 2>/dev/null
                rm -f /swapfile
                sed -i '/\/swapfile/d' /etc/fstab
                zramctl --reset /dev/zram0 2>/dev/null
                rm -f $SYSCTL_CONF /etc/dnsmasq.d/vps-speed.conf
                systemctl stop vps-noise dnsmasq >/dev/null 2>&1
                sysctl --system
                echo -e "${GREEN}[+] Сброс выполнен.${NC}"; sleep 2 ;;
            0) exit 0 ;;
            *) echo -e "${RED}[!] Неверный выбор.${NC}"; sleep 1 ;;
        esac
    done
}

check_root
main_menu
