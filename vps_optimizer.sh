#!/bin/bash
# shellcheck disable=SC2059

# ==============================================================================
# VPS Global Optimization Script (v8.2 PHOENIX-Z++)
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

# v8.6: TTY/NO_COLOR-detect — если stdout не tty или установлен NO_COLOR (https://no-color.org),
# выключаем ANSI escape-последовательности. Иначе грязные '^[[31m' попадают в логи/pipe,
# которые потом грепаются и обрабатываются скриптами (cron/Ansible/Loki).
# Можно форсировать включение через FORCE_COLOR=1 (для CI с цветным output).
LANG_CONF="/etc/vps-optimizer.lang"
if [ -n "${FORCE_COLOR:-}" ]; then
    _vps_use_color=1
elif [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    _vps_use_color=0
else
    _vps_use_color=1
fi

# Цвета (или пустые строки если color disabled)
if [ "$_vps_use_color" = "1" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    GRAY='\033[0;90m'
    NC='\033[0m'
    BOLD='\033[1m'
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    MAGENTA=''
    GRAY=''
    NC=''
    BOLD=''
fi

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
AUDIT_LOG="/var/log/vps-optimizer-audit.log"
DEBUG_LOG="/var/log/vps-optimizer-debug.log"
LOCK_FILE="/var/lock/vps-optimizer.lock"
SNAPSHOT_DIR="/var/backups/vps-optimizer"
HEALTH_DIR="/run/vps-noise"
HEALTH_FILE="$HEALTH_DIR/health.json"
# shellcheck disable=SC2034  # used in deploy_noise_generator
NOISE_STATE_DIR="/var/lib/vps-noise"
INTERNET_PROBE_URL="https://1.1.1.1/cdn-cgi/trace"
EXPORT_FORMAT_VERSION=2
SCRIPT_VERSION="8.7"

# Глобальные флаги (управляются через CLI)
DRY_RUN=0
QUIET=0
PRESET=""
DEBUG=0
FORCE=0
IMPERSONATE=0
ECMP=0
JSON=0
CLI_MODE=0
VPN_FORCE=0          # --vpn: явно настраиваем под VPN-роутинг (rp_filter=2, ip_forward=1)
NO_ROLLBACK=0        # --no-rollback: отключить auto-rollback по connectivity-check
SOFT_RESET=0         # reset --soft: не трогать DNS/noise/swap, только sysctl
JSON_LOGS=0          # --json-logs: structured logging для ELK/Loki (v8.6)
LEARN_MODE=0         # --learn: dry-run + diff с rationale, без записи (v8.6)

# v8.6: i18n. Default=en. Resolve order: $LC_VPS env > /etc/vps-optimizer.lang > "en".
# Поддерживаемые: en, ru, de, fr, zh. Невалидное значение → fallback на 'en'.
SCRIPT_LANG="${LC_VPS:-}"
if [ -z "$SCRIPT_LANG" ] && [ -r "$LANG_CONF" ]; then
    SCRIPT_LANG=$(head -1 "$LANG_CONF" 2>/dev/null | tr -d '[:space:]')
fi
case "$SCRIPT_LANG" in
    en|ru|de|fr|zh) ;;
    *) SCRIPT_LANG="en" ;;
esac

# Cron-friendly exit codes — стабильный API для cron/Ansible/мониторинга.
# shellcheck disable=SC2034  # часть кодов используется только внешними скриптами
EXIT_OK=0
# shellcheck disable=SC2034
EXIT_ALREADY_APPLIED=10  # idempotent: всё совпадает, ничего не делали
# shellcheck disable=SC2034
EXIT_NO_INTERNET=20      # не смогли проверить связь до apply
# shellcheck disable=SC2034
EXIT_HYPERVISOR_BLOCK=30 # хост запретил всё, что мы пытались сделать
EXIT_LOCK_BUSY=40        # другой apply уже идёт
EXIT_INVALID_ARGS=50     # неверный preset/команда
EXIT_ROLLED_BACK=60      # apply применился, но связь упала → откатились

# Сводки sysctl/sysfs/ethtool — заполняются в процессе apply, печатаются в self_test
SYSCTL_OK=()
SYSCTL_SKIP=()
SYSFS_OK=()
SYSFS_SKIP=()

# ===================================================================
#  v8.6: i18n — переводы пользовательских сообщений
# ===================================================================
# Архитектура: ассоциативные массивы I18N_<LANG> с ключами (snake_case),
# функция _t возвращает строку для текущего $SCRIPT_LANG, fallback на EN,
# fallback на сам ключ. Это позволяет добавлять/переводить инкрементально:
# непереведённый ключ просто покажет английский (или сам ключ).
#
# Намеренно покрываем только ~80 наиболее видимых строк (help/usage/main errors/
# command headers). Низкоуровневые debug-сообщения остаются в исходном языке.
# shellcheck disable=SC2034  # I18N_RU/DE/FR/ZH used via nameref in _t()
declare -A I18N_EN I18N_RU I18N_DE I18N_FR I18N_ZH

# --- English (default, источник истины) ---
I18N_EN[err_root]="[!] Run as root."
I18N_EN[err_lock_busy]="[!] Another vps_optimizer instance is running (lock=%s)."
I18N_EN[err_lock_busy_hint]="    Pass --force to ignore."
I18N_EN[lang_set]="[+] Language set to %s. Saved to %s."
I18N_EN[lang_unsupported]="[!] Unsupported language: %s. Supported: en, ru, de, fr, zh."
I18N_EN[lang_current]="Current language: %s"
I18N_EN[lang_usage]="Usage: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_EN[learn_header]="=== --learn mode: showing what WOULD change ==="
I18N_EN[learn_footer]="No files were modified. Run without --learn to apply."
I18N_EN[json_logs_on]="JSON-logs mode active (structured for ELK/Loki)"
I18N_EN[help_title]="VPS Optimizer v%s"
I18N_EN[help_usage]="USAGE:"
I18N_EN[help_commands]="COMMANDS:"
I18N_EN[help_global_flags]="GLOBAL FLAGS:"
I18N_EN[help_exit_codes]="EXIT CODES (for cron/Ansible):"
I18N_EN[help_examples]="EXAMPLES:"
I18N_EN[help_config_files]="CONFIG FILES:"
I18N_EN[help_logs]="LOGS:"
I18N_EN[help_see_also]="SEE ALSO:"
I18N_EN[cmd_install]="Install Phoenix components"
I18N_EN[cmd_apply]="Apply sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)"
I18N_EN[cmd_status]="Show state dashboard (or JSON for machines)"
I18N_EN[cmd_self_test]="Re-verify applied settings"
I18N_EN[cmd_audit]="Deep diagnostics (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_EN[cmd_doctor]="Actionable diagnostics with recommendations"
I18N_EN[cmd_why]="Explain why a specific sysctl is set this way"
I18N_EN[cmd_top]="TUI: live top-connections, conntrack util, retransmits"
I18N_EN[cmd_mtr]="Bundled mtr with loss prediction (requires mtr)"
I18N_EN[cmd_prom_push]="Push Prometheus metrics to a pushgateway"
I18N_EN[cmd_stealth_test]="JA3-leak self-check via ja3er.com"
I18N_EN[cmd_audit_syslog]="Forward audit-log to remote syslog"
I18N_EN[cmd_backup_config]="Snapshot configs to rclone-remote"
I18N_EN[cmd_playbook]="Pre-baked roles: hysteria2-host|wg-vpn-server|web-frontend"
I18N_EN[cmd_health_watch]="Periodic doctor systemd-timer (every 5 min)"
I18N_EN[cmd_dns_doq]="Install DNS-over-QUIC (opt-in, requires AdGuard Home)"
I18N_EN[cmd_dns_dnssec]="Enable DNSSEC validation in unbound (opt-in)"
I18N_EN[cmd_logs]="Last N lines of journals (run/journalctl/dmesg/audit)"
I18N_EN[cmd_preset]="Save preset for future apply"
I18N_EN[cmd_noise]="Manage noise generator"
I18N_EN[cmd_wg_setup]="WireGuard helper: MTU autodetect, conntrack rules"
I18N_EN[cmd_dns]="Manage DNS configuration"
I18N_EN[cmd_swap]="Create swap file of given size in GB"
I18N_EN[cmd_benchmark]="Measure ping to popular endpoints"
I18N_EN[cmd_compare]="Save ping baseline / show diff (default: 1.1.1.1)"
I18N_EN[cmd_harden]="Opt-in security (does NOT change apply default)"
I18N_EN[cmd_prom_metrics]="Dump Prometheus metrics to stdout"
I18N_EN[cmd_prom_serve]="Run Prometheus exporter (default port 9777)"
I18N_EN[cmd_reset]="Full rollback / --soft = sysctl only"
I18N_EN[cmd_uninstall]="Full removal: reset + delete script itself"
I18N_EN[cmd_export]="Export all configs to archive (with manifest)"
I18N_EN[cmd_import]="Import exported configs (with version check)"
I18N_EN[cmd_update]="Update script (with SHA256 verification)"
I18N_EN[cmd_config]="Configuration: lang <code> | show"
I18N_EN[cmd_help]="This help"
I18N_EN[flag_dry_run]="Only show what would change"
I18N_EN[flag_quiet]="Minimal output (for scripts/cron)"
I18N_EN[flag_debug]="Verbose log to %s"
I18N_EN[flag_force]="Ignore lock / confirmations"
I18N_EN[flag_preset]="Use a specific preset (see apply)"
I18N_EN[flag_impersonate]="Use curl-impersonate for noise (if installed)"
I18N_EN[flag_ecmp]="Enable ECMP/multipath (for multi-NIC bare-metal)"
I18N_EN[flag_vpn]="Explicit VPN mode: rp_filter=2, accept_local, ip_forward"
I18N_EN[flag_no_rollback]="Disable auto-rollback on connectivity check"
I18N_EN[flag_soft]="Soft mode (for reset): sysctl only, keep DNS/noise"
I18N_EN[flag_boot]="Boot mode (for apply): create one-shot systemd unit"
I18N_EN[flag_json]="JSON output (for status/audit)"
I18N_EN[flag_json_logs]="Structured JSON-logs to RUN_LOG (ELK/Loki)"
I18N_EN[flag_no_color]="Disable ANSI colors (auto in pipe/file)"
I18N_EN[flag_learn]="--learn: dry-run with detailed diff and rationale"

# --- Russian (исторический язык скрипта — большинство строк УЖЕ ru) ---
I18N_RU[err_root]="[!] Запустите от имени root."
I18N_RU[err_lock_busy]="[!] Другой инстанс vps_optimizer уже работает (lock=%s)."
I18N_RU[err_lock_busy_hint]="    Запусти с --force чтобы проигнорировать."
I18N_RU[lang_set]="[+] Язык установлен: %s. Сохранён в %s."
I18N_RU[lang_unsupported]="[!] Язык не поддерживается: %s. Доступны: en, ru, de, fr, zh."
I18N_RU[lang_current]="Текущий язык: %s"
I18N_RU[lang_usage]="Использование: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_RU[learn_header]="=== режим --learn: что бы поменялось ==="
I18N_RU[learn_footer]="Никакие файлы не изменены. Без --learn — реально применить."
I18N_RU[json_logs_on]="JSON-logs режим включён (structured для ELK/Loki)"
I18N_RU[help_title]="VPS Optimizer v%s"
I18N_RU[help_usage]="ИСПОЛЬЗОВАНИЕ:"
I18N_RU[help_commands]="КОМАНДЫ:"
I18N_RU[help_global_flags]="ГЛОБАЛЬНЫЕ ФЛАГИ:"
I18N_RU[help_exit_codes]="EXIT КОДЫ (для cron/Ansible):"
I18N_RU[help_examples]="ПРИМЕРЫ:"
I18N_RU[help_config_files]="ФАЙЛЫ КОНФИГА:"
I18N_RU[help_logs]="ЛОГИ:"
I18N_RU[help_see_also]="СМ. ТАКЖЕ:"
I18N_RU[cmd_install]="Установить компоненты Phoenix"
I18N_RU[cmd_apply]="Применить sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)"
I18N_RU[cmd_status]="Показать дашборд состояния (или JSON для машин)"
I18N_RU[cmd_self_test]="Перепроверить применённые настройки"
I18N_RU[cmd_audit]="Глубокая диагностика (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_RU[cmd_doctor]="Actionable-диагностика с рекомендациями"
I18N_RU[cmd_why]="Объяснить почему конкретный sysctl такой"
I18N_RU[cmd_top]="TUI: live топ-conn, conntrack, retransmits"
I18N_RU[cmd_mtr]="Bundled mtr с прогнозом потерь (требует mtr)"
I18N_RU[cmd_prom_push]="Push Prometheus метрик в pushgateway"
I18N_RU[cmd_stealth_test]="Само-проверка JA3-leak'а через ja3er.com"
I18N_RU[cmd_audit_syslog]="Пересылать audit-log в remote syslog"
I18N_RU[cmd_backup_config]="Выгрузить конфиги в rclone-remote"
I18N_RU[cmd_playbook]="Готовые роли: hysteria2-host|wg-vpn-server|web-frontend"
I18N_RU[cmd_health_watch]="Систёмный таймер doctor каждые 5 мин"
I18N_RU[cmd_dns_doq]="Установка DNS-over-QUIC (opt-in, требует AdGuard Home)"
I18N_RU[cmd_dns_dnssec]="Включить DNSSEC validation в unbound (opt-in)"
I18N_RU[cmd_logs]="Последние N строк журнала (run/journalctl/dmesg/audit)"
I18N_RU[cmd_preset]="Сохранить пресет на будущие apply"
I18N_RU[cmd_noise]="Управление шумогенератором"
I18N_RU[cmd_wg_setup]="WireGuard helper: автодетект MTU, conntrack-rules"
I18N_RU[cmd_dns]="Управление DNS"
I18N_RU[cmd_swap]="Создать swap-файл указанного размера в ГБ"
I18N_RU[cmd_benchmark]="Замерить пинг до набора популярных endpoints"
I18N_RU[cmd_compare]="Сохранить ping baseline / показать diff (default: 1.1.1.1)"
I18N_RU[cmd_harden]="Opt-in security (НЕ меняет дефолт apply)"
I18N_RU[cmd_prom_metrics]="Сдампить Prometheus-метрики на stdout"
I18N_RU[cmd_prom_serve]="Поднять Prometheus exporter (default port 9777)"
I18N_RU[cmd_reset]="Полный откат / --soft = только sysctl"
I18N_RU[cmd_uninstall]="Полное удаление: сбрасывает + сносит сам скрипт"
I18N_RU[cmd_export]="Выгрузить все конфиги в архив (с manifest)"
I18N_RU[cmd_import]="Накатить выгруженные конфиги (с проверкой версии)"
I18N_RU[cmd_update]="Обновить скрипт (с SHA256 verification)"
I18N_RU[cmd_config]="Конфигурация: lang <код> | show"
I18N_RU[cmd_help]="Эта справка"
I18N_RU[flag_dry_run]="Только показать, что бы изменилось"
I18N_RU[flag_quiet]="Минимум вывода (для скриптов/cron)"
I18N_RU[flag_debug]="Подробный лог в %s"
I18N_RU[flag_force]="Игнорировать lock / подтверждения"
I18N_RU[flag_preset]="Использовать конкретный пресет (см. apply)"
I18N_RU[flag_impersonate]="Использовать curl-impersonate в шуме (если установлен)"
I18N_RU[flag_ecmp]="Включить ECMP/multipath (для multi-NIC bare-metal)"
I18N_RU[flag_vpn]="Явно VPN-режим: rp_filter=2, accept_local, ip_forward"
I18N_RU[flag_no_rollback]="Отключить auto-rollback по connectivity-check"
I18N_RU[flag_soft]="Soft-режим (для reset): только sysctl, не трогать DNS/noise"
I18N_RU[flag_boot]="Boot-режим (для apply): создать one-shot systemd unit"
I18N_RU[flag_json]="Вывод в JSON (для status/audit)"
I18N_RU[flag_json_logs]="Structured JSON-logs в RUN_LOG (ELK/Loki)"
I18N_RU[flag_no_color]="Выключить ANSI цвета (auto в pipe/file)"
I18N_RU[flag_learn]="--learn: dry-run с детальным diff и rationale"

# --- Deutsch ---
I18N_DE[err_root]="[!] Als root ausführen."
I18N_DE[err_lock_busy]="[!] Eine andere vps_optimizer-Instanz läuft (lock=%s)."
I18N_DE[err_lock_busy_hint]="    --force zum Ignorieren übergeben."
I18N_DE[lang_set]="[+] Sprache gesetzt: %s. Gespeichert in %s."
I18N_DE[lang_unsupported]="[!] Sprache nicht unterstützt: %s. Erlaubt: en, ru, de, fr, zh."
I18N_DE[lang_current]="Aktuelle Sprache: %s"
I18N_DE[lang_usage]="Verwendung: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_DE[learn_header]="=== --learn-Modus: was geändert würde ==="
I18N_DE[learn_footer]="Keine Datei wurde geändert. Ohne --learn anwenden."
I18N_DE[json_logs_on]="JSON-Log-Modus aktiv (strukturiert für ELK/Loki)"
I18N_DE[help_title]="VPS Optimizer v%s"
I18N_DE[help_usage]="VERWENDUNG:"
I18N_DE[help_commands]="BEFEHLE:"
I18N_DE[help_global_flags]="GLOBALE FLAGS:"
I18N_DE[help_exit_codes]="EXIT-CODES (für cron/Ansible):"
I18N_DE[help_examples]="BEISPIELE:"
I18N_DE[help_config_files]="KONFIG-DATEIEN:"
I18N_DE[help_logs]="LOGS:"
I18N_DE[help_see_also]="SIEHE AUCH:"
I18N_DE[cmd_install]="Phoenix-Komponenten installieren"
I18N_DE[cmd_apply]="sysctl/sysfs/ZRAM anwenden (NAME: balanced|proxy|web)"
I18N_DE[cmd_status]="Status-Dashboard anzeigen (oder JSON für Maschinen)"
I18N_DE[cmd_self_test]="Angewendete Einstellungen erneut prüfen"
I18N_DE[cmd_audit]="Tiefe Diagnose (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_DE[cmd_doctor]="Actionable Diagnose mit Empfehlungen"
I18N_DE[cmd_why]="Erklären warum ein bestimmter sysctl so gesetzt ist"
I18N_DE[cmd_top]="TUI: Live Top-Verbindungen, conntrack-Auslastung, retransmits"
I18N_DE[cmd_mtr]="mtr mit Verlustvorhersage (benötigt mtr)"
I18N_DE[cmd_prom_push]="Prometheus-Metriken zu Pushgateway senden"
I18N_DE[cmd_stealth_test]="JA3-Leak-Selbstprüfung via ja3er.com"
I18N_DE[cmd_audit_syslog]="audit-log an Remote-Syslog weiterleiten"
I18N_DE[cmd_backup_config]="Konfig-Snapshots zu rclone-remote"
I18N_DE[cmd_playbook]="Vorgefertigte Rollen: hysteria2-host|wg-vpn-server|web-frontend"
I18N_DE[cmd_health_watch]="Periodischer doctor-Timer (alle 5 Min)"
I18N_DE[cmd_dns_doq]="DNS-over-QUIC (opt-in, benötigt AdGuard Home)"
I18N_DE[cmd_dns_dnssec]="DNSSEC-Validierung in unbound (opt-in)"
I18N_DE[cmd_logs]="Letzte N Journal-Zeilen (run/journalctl/dmesg/audit)"
I18N_DE[cmd_preset]="Preset für künftige apply-Aufrufe speichern"
I18N_DE[cmd_noise]="Noise-Generator verwalten"
I18N_DE[cmd_wg_setup]="WireGuard-Helper: MTU-Autodetect, conntrack"
I18N_DE[cmd_dns]="DNS-Konfiguration verwalten"
I18N_DE[cmd_swap]="Swap-Datei in angegebener GB-Grösse erstellen"
I18N_DE[cmd_benchmark]="Ping zu populären Endpoints messen"
I18N_DE[cmd_compare]="Ping-Baseline speichern / Diff anzeigen (default: 1.1.1.1)"
I18N_DE[cmd_harden]="Opt-in Sicherheit (ändert apply-Default NICHT)"
I18N_DE[cmd_prom_metrics]="Prometheus-Metriken nach stdout"
I18N_DE[cmd_prom_serve]="Prometheus-Exporter starten (default port 9777)"
I18N_DE[cmd_reset]="Voller Rollback / --soft = nur sysctl"
I18N_DE[cmd_uninstall]="Volle Entfernung: reset + Skript löschen"
I18N_DE[cmd_export]="Alle Konfigs in Archiv exportieren (mit manifest)"
I18N_DE[cmd_import]="Exportierte Konfigs importieren (mit Versionsprüfung)"
I18N_DE[cmd_update]="Skript aktualisieren (mit SHA256-Verifikation)"
I18N_DE[cmd_config]="Konfiguration: lang <code> | show"
I18N_DE[cmd_help]="Diese Hilfe"

# --- Français ---
I18N_FR[err_root]="[!] Exécutez en tant que root."
I18N_FR[err_lock_busy]="[!] Une autre instance vps_optimizer est en cours (lock=%s)."
I18N_FR[err_lock_busy_hint]="    Utilisez --force pour ignorer."
I18N_FR[lang_set]="[+] Langue définie: %s. Sauvegardée dans %s."
I18N_FR[lang_unsupported]="[!] Langue non supportée: %s. Disponibles: en, ru, de, fr, zh."
I18N_FR[lang_current]="Langue actuelle: %s"
I18N_FR[lang_usage]="Utilisation: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_FR[learn_header]="=== mode --learn: ce qui changerait ==="
I18N_FR[learn_footer]="Aucun fichier modifié. Sans --learn pour appliquer."
I18N_FR[json_logs_on]="Mode JSON-logs actif (structuré pour ELK/Loki)"
I18N_FR[help_title]="VPS Optimizer v%s"
I18N_FR[help_usage]="UTILISATION:"
I18N_FR[help_commands]="COMMANDES:"
I18N_FR[help_global_flags]="DRAPEAUX GLOBAUX:"
I18N_FR[help_exit_codes]="CODES DE SORTIE (pour cron/Ansible):"
I18N_FR[help_examples]="EXEMPLES:"
I18N_FR[help_config_files]="FICHIERS DE CONFIG:"
I18N_FR[help_logs]="LOGS:"
I18N_FR[help_see_also]="VOIR AUSSI:"
I18N_FR[cmd_install]="Installer composants Phoenix"
I18N_FR[cmd_apply]="Appliquer sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)"
I18N_FR[cmd_status]="Tableau de bord d'état (ou JSON pour machines)"
I18N_FR[cmd_self_test]="Re-vérifier les paramètres appliqués"
I18N_FR[cmd_audit]="Diagnostic profond (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_FR[cmd_doctor]="Diagnostic actionnable avec recommandations"
I18N_FR[cmd_why]="Expliquer pourquoi un sysctl est ainsi"
I18N_FR[cmd_top]="TUI: top connexions live, conntrack, retransmits"
I18N_FR[cmd_mtr]="mtr avec prévision de perte (nécessite mtr)"
I18N_FR[cmd_prom_push]="Pousser métriques Prometheus vers pushgateway"
I18N_FR[cmd_stealth_test]="Auto-test JA3-leak via ja3er.com"
I18N_FR[cmd_audit_syslog]="Transférer audit-log vers syslog distant"
I18N_FR[cmd_backup_config]="Snapshot configs vers rclone-remote"
I18N_FR[cmd_playbook]="Rôles prédéfinis: hysteria2-host|wg-vpn-server|web-frontend"
I18N_FR[cmd_health_watch]="Timer doctor périodique (toutes 5 min)"
I18N_FR[cmd_dns_doq]="Installer DNS-over-QUIC (opt-in, nécessite AdGuard Home)"
I18N_FR[cmd_dns_dnssec]="Activer validation DNSSEC dans unbound (opt-in)"
I18N_FR[cmd_logs]="N dernières lignes de journaux"
I18N_FR[cmd_preset]="Sauvegarder preset pour futurs apply"
I18N_FR[cmd_noise]="Gérer le générateur de bruit"
I18N_FR[cmd_wg_setup]="Helper WireGuard: MTU auto, conntrack"
I18N_FR[cmd_dns]="Gérer configuration DNS"
I18N_FR[cmd_swap]="Créer fichier swap de taille donnée en Go"
I18N_FR[cmd_benchmark]="Mesurer ping vers endpoints populaires"
I18N_FR[cmd_compare]="Sauvegarder baseline / afficher diff (défaut: 1.1.1.1)"
I18N_FR[cmd_harden]="Sécurité opt-in (ne modifie PAS le défaut apply)"
I18N_FR[cmd_prom_metrics]="Dump métriques Prometheus sur stdout"
I18N_FR[cmd_prom_serve]="Lancer exporter Prometheus (port défaut 9777)"
I18N_FR[cmd_reset]="Rollback complet / --soft = sysctl seulement"
I18N_FR[cmd_uninstall]="Suppression totale: reset + script lui-même"
I18N_FR[cmd_export]="Exporter toutes configs en archive (avec manifest)"
I18N_FR[cmd_import]="Importer configs exportées (avec vérif version)"
I18N_FR[cmd_update]="Mettre à jour le script (avec vérif SHA256)"
I18N_FR[cmd_config]="Configuration: lang <code> | show"
I18N_FR[cmd_help]="Cette aide"

# --- 中文 (简体) ---
I18N_ZH[err_root]="[!] 请以 root 身份运行。"
I18N_ZH[err_lock_busy]="[!] 另一个 vps_optimizer 实例正在运行 (lock=%s)。"
I18N_ZH[err_lock_busy_hint]="    使用 --force 忽略。"
I18N_ZH[lang_set]="[+] 语言已设置: %s。已保存到 %s。"
I18N_ZH[lang_unsupported]="[!] 不支持的语言: %s。可用: en, ru, de, fr, zh。"
I18N_ZH[lang_current]="当前语言: %s"
I18N_ZH[lang_usage]="用法: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
I18N_ZH[learn_header]="=== --learn 模式: 显示将要更改的内容 ==="
I18N_ZH[learn_footer]="没有文件被修改。去掉 --learn 即可实际应用。"
I18N_ZH[json_logs_on]="JSON-logs 模式已启用 (结构化用于 ELK/Loki)"
I18N_ZH[help_title]="VPS Optimizer v%s"
I18N_ZH[help_usage]="用法:"
I18N_ZH[help_commands]="命令:"
I18N_ZH[help_global_flags]="全局参数:"
I18N_ZH[help_exit_codes]="退出码 (用于 cron/Ansible):"
I18N_ZH[help_examples]="示例:"
I18N_ZH[help_config_files]="配置文件:"
I18N_ZH[help_logs]="日志:"
I18N_ZH[help_see_also]="另请参阅:"
I18N_ZH[cmd_install]="安装 Phoenix 组件"
I18N_ZH[cmd_apply]="应用 sysctl/sysfs/ZRAM (NAME: balanced|proxy|web)"
I18N_ZH[cmd_status]="显示状态仪表板 (或 JSON 用于程序)"
I18N_ZH[cmd_self_test]="重新检查已应用的设置"
I18N_ZH[cmd_audit]="深度诊断 (drift, conntrack, RPS, dnscrypt-proxy)"
I18N_ZH[cmd_doctor]="可操作诊断与建议"
I18N_ZH[cmd_why]="解释某个 sysctl 为何如此设置"
I18N_ZH[cmd_top]="TUI: 实时连接、conntrack、重传"
I18N_ZH[cmd_mtr]="带丢包预测的 mtr (需要 mtr)"
I18N_ZH[cmd_prom_push]="推送 Prometheus 指标到 pushgateway"
I18N_ZH[cmd_stealth_test]="通过 ja3er.com 自检 JA3 泄漏"
I18N_ZH[cmd_audit_syslog]="将 audit-log 转发到远程 syslog"
I18N_ZH[cmd_backup_config]="将配置快照到 rclone-remote"
I18N_ZH[cmd_playbook]="预设角色: hysteria2-host|wg-vpn-server|web-frontend"
I18N_ZH[cmd_health_watch]="周期性 doctor 定时器 (每5分钟)"
I18N_ZH[cmd_dns_doq]="安装 DNS-over-QUIC (opt-in, 需要 AdGuard Home)"
I18N_ZH[cmd_dns_dnssec]="启用 unbound 中的 DNSSEC 验证 (opt-in)"
I18N_ZH[cmd_logs]="最新 N 行日志"
I18N_ZH[cmd_preset]="保存 preset 供后续 apply 使用"
I18N_ZH[cmd_noise]="管理噪声生成器"
I18N_ZH[cmd_wg_setup]="WireGuard 助手: MTU 自动检测、conntrack"
I18N_ZH[cmd_dns]="管理 DNS 配置"
I18N_ZH[cmd_swap]="创建指定大小 (GB) 的 swap 文件"
I18N_ZH[cmd_benchmark]="测量到流行端点的 ping"
I18N_ZH[cmd_compare]="保存 ping 基线 / 显示差异 (默认: 1.1.1.1)"
I18N_ZH[cmd_harden]="可选安全 (不改变 apply 默认行为)"
I18N_ZH[cmd_prom_metrics]="将 Prometheus 指标输出到 stdout"
I18N_ZH[cmd_prom_serve]="启动 Prometheus exporter (默认端口 9777)"
I18N_ZH[cmd_reset]="完全回滚 / --soft = 仅 sysctl"
I18N_ZH[cmd_uninstall]="完全卸载: reset + 删除脚本本身"
I18N_ZH[cmd_export]="将所有配置导出到归档 (含 manifest)"
I18N_ZH[cmd_import]="导入导出的配置 (含版本检查)"
I18N_ZH[cmd_update]="更新脚本 (含 SHA256 验证)"
I18N_ZH[cmd_config]="配置: lang <code> | show"
I18N_ZH[cmd_help]="此帮助"

# Чтобы shellcheck не ругался SC2034 на «unused» массивы (они доступаются
# только через nameref в _t() — статический анализатор это не видит).
: "${I18N_RU[err_root]}" "${I18N_DE[err_root]}" "${I18N_FR[err_root]}" "${I18N_ZH[err_root]}"

# _t key — возвращает локализованную строку.
# Поиск: I18N_<LANG> → I18N_EN → ключ как есть.
# Если переданы доп.аргументы, они подставляются через printf '%s'.
_t() {
    local key="$1"; shift || true
    local arr_name="I18N_${SCRIPT_LANG^^}"
    local -n arr="$arr_name" 2>/dev/null
    local fmt="${arr[$key]:-}"
    [ -z "$fmt" ] && fmt="${I18N_EN[$key]:-$key}"
    if [ $# -gt 0 ]; then
        # shellcheck disable=SC2059
        printf "$fmt\n" "$@"
    else
        printf "%s\n" "$fmt"
    fi
}

print_header() {
    [ "$QUIET" = "1" ] && return
    clear
    echo -e "${MAGENTA}${BOLD}"
    echo "================================================================="
    echo "       ULTRA VPS ACCELERATOR v8.2 (PHOENIX-Z++)                  "
    echo "================================================================="
    echo -e "  Probe-then-Write | XPS+RPS+IRQ | conntrack | MPTCP | THP    "
    echo -e "  Presets: balanced / proxy / web    Stealth: iOS+RU+APT     "
    echo -e "=================================================================${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}$(_t err_root)${NC}"
        exit 1
    fi
}

# Лог в файл (перезаписывается при каждом запуске apply, рядом — на консоль)
# v8.6: при --json-logs пишем structured JSON-line вместо plain-line
# (для ELK/Loki/Vector). Поля: ts, level, version, host, msg.
_log() {
    local level="$1"; shift
    local msg="$*"
    [ "$QUIET" = "1" ] || echo -e "$msg"
    local ts plain
    ts=$(date -u +%FT%T.%3NZ)
    plain=$(echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g')
    if [ "$JSON_LOGS" = "1" ]; then
        # Минимальное JSON-эскейпирование (\, ", \n, \t).
        local esc="$plain"
        esc="${esc//\\/\\\\}"
        esc="${esc//\"/\\\"}"
        esc="${esc//$'\n'/\\n}"
        esc="${esc//$'\t'/\\t}"
        printf '{"ts":"%s","level":"%s","version":"%s","host":"%s","msg":"%s"}\n' \
            "$ts" "$level" "$SCRIPT_VERSION" "${HOSTNAME:-unknown}" "$esc" \
            >> "$RUN_LOG" 2>/dev/null || true
    else
        echo "[$ts] [$level] $plain" >> "$RUN_LOG" 2>/dev/null || true
    fi
}

# Audit-log: фиксирует каждую mutating-команду (apply / reset / dns / noise / harden / uninstall).
# Пишется в отдельный append-only лог, не зависящий от $QUIET.
_audit() {
    local action="$1"; shift
    local user="${SUDO_USER:-${USER:-root}}"
    local detail="$*"
    mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true
    echo "[$(date -u +%FT%TZ)] user=$user action=$action $detail" >> "$AUDIT_LOG" 2>/dev/null || true
}

# Debug-log: подробный вывод каждой sysctl/sysfs-записи. Включается флагом --debug.
_debug() {
    [ "$DEBUG" = "1" ] || return 0
    mkdir -p "$(dirname "$DEBUG_LOG")" 2>/dev/null || true
    echo "[$(date -u +%FT%T.%3NZ)] $*" >> "$DEBUG_LOG" 2>/dev/null || true
}

# /dev/urandom-based случайное число в диапазоне [a, b]. Используем когда $RANDOM
# даёт коллизии в параллельных bash-процессах (например loop_ios + loop_news запущены
# одновременно — получают одинаковую seed, тянут одинаковые URL'ы → паттерн).
urand_range() {
    local lo="$1" hi="$2" span r
    span=$(( hi - lo + 1 ))
    [ "$span" -le 0 ] && { echo "$lo"; return; }
    if [ -r /dev/urandom ]; then
        r=$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' ')
        [ -z "$r" ] && r=$RANDOM
        echo $(( r % span + lo ))
    else
        echo $(( RANDOM % span + lo ))
    fi
}

# Lock-файл для предотвращения одновременных apply/reset.
acquire_lock() {
    [ "$DRY_RUN" = "1" ] && return 0
    [ "$FORCE" = "1" ] && return 0
    mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
    exec 9>"$LOCK_FILE" 2>/dev/null || return 0
    if ! flock -n 9 2>/dev/null; then
        echo -e "${RED}$(_t err_lock_busy "$LOCK_FILE")${NC}"
        echo -e "${GRAY}$(_t err_lock_busy_hint)${NC}"
        return 1
    fi
    return 0
}

release_lock() {
    exec 9>&- 2>/dev/null || true
}

# Быстрая проверка наличия интернета — чтобы не сломать DNS если связь уже отвалилась.
check_internet() {
    local timeout=3
    if curl -sf --max-time "$timeout" "$INTERNET_PROBE_URL" >/dev/null 2>&1; then
        return 0
    fi
    if timeout "$timeout" bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
        return 0
    fi
    return 1
}

# Простой SHA256 — для idempotency и self_update integrity check
file_sha256() {
    local f="$1"
    [ -f "$f" ] || { echo ""; return; }
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
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
        _debug "sysctl SKIP unsupported: $key=$value"
        return 1
    fi
    if [ "$DRY_RUN" = "1" ]; then
        SYSCTL_OK+=("$key=$value (dry-run)")
        [ -n "$SYSCTL_TMP" ] && echo "$key = $value" >> "$SYSCTL_TMP"
        _debug "sysctl DRY: $key=$value"
        # v8.6 --learn: показываем diff текущее → желаемое прямо в stdout
        if [ "$LEARN_MODE" = "1" ]; then
            local _cur
            _cur=$(sysctl -n "$key" 2>/dev/null || echo "?")
            if [ "$_cur" != "$value" ]; then
                echo -e "  ${YELLOW}~${NC} ${BOLD}$key${NC}: ${GRAY}$_cur${NC} → ${GREEN}$value${NC}"
            fi
        fi
        return 0
    fi
    if sysctl -w "$key=$value" >/dev/null 2>&1; then
        SYSCTL_OK+=("$key=$value")
        [ -n "$SYSCTL_TMP" ] && echo "$key = $value" >> "$SYSCTL_TMP"
        _debug "sysctl OK: $key=$value"
        return 0
    else
        SYSCTL_SKIP+=("$key=denied")
        _debug "sysctl DENIED: $key=$value"
        return 1
    fi
}

# Безопасная запись в /sys или /proc: проверяем существование и writability.
sysfs_safe() {
    local path="$1" value="$2"
    if [ ! -e "$path" ]; then
        SYSFS_SKIP+=("$path:missing")
        _debug "sysfs SKIP missing: $path"
        return 1
    fi
    if [ "$DRY_RUN" = "1" ]; then
        SYSFS_OK+=("$path=$value (dry-run)")
        _debug "sysfs DRY: $path=$value"
        if [ "$LEARN_MODE" = "1" ]; then
            local _cur
            _cur=$(cat "$path" 2>/dev/null || echo "?")
            if [ "$_cur" != "$value" ]; then
                echo -e "  ${YELLOW}~${NC} ${BOLD}$path${NC}: ${GRAY}$_cur${NC} → ${GREEN}$value${NC}"
            fi
        fi
        return 0
    fi
    if echo "$value" > "$path" 2>/dev/null; then
        SYSFS_OK+=("$path=$value")
        _debug "sysfs OK: $path=$value"
        return 0
    else
        SYSFS_SKIP+=("$path:denied")
        _debug "sysfs DENIED: $path=$value"
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

# Detect VPS-провайдера через dmidecode / hostname / IP-ranges.
# Возвращает: hetzner|digitalocean|vultr|aws|gcp|azure|aeza|timeweb|firstbyte|generic
detect_provider() {
    local sys_vendor sys_product hostname_lc
    sys_vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null | tr '[:upper:]' '[:lower:]')
    sys_product=$(cat /sys/class/dmi/id/product_name 2>/dev/null | tr '[:upper:]' '[:lower:]')
    hostname_lc=$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]')

    # DMI-сигнатуры провайдеров
    case "$sys_vendor$sys_product" in
        *hetzner*)        echo hetzner;        return ;;
        *digitalocean*)   echo digitalocean;   return ;;
        *vultr*)          echo vultr;          return ;;
        *amazon*|*aws*)   echo aws;            return ;;
        *google*)         echo gcp;            return ;;
        *microsoft*|*hyperv*) echo azure;      return ;;
        *oracle*)         echo oracle;         return ;;
    esac
    # hostname-эвристика — только если dmi не сработал (Aeza/Timeweb/Firstbyte
    # часто включают название в hostname, но это менее надёжно: 'vultr.example.com'
    # не значит что VPS у Vultr). Q8 fix v8.3: матчим только если домен содержит
    # суффикс провайдера, не любую подстроку.
    case "$hostname_lc" in
        *.aeza.net|*.aeza.online|aeza-*)        echo aeza;      return ;;
        *.timeweb.cloud|*.timeweb.ru|timeweb-*) echo timeweb;   return ;;
        *.firstbyte.ru|*.1stbyte.ru|fb-*)       echo firstbyte; return ;;
    esac
    echo generic
}

# Безопасная проверка: можем ли мы включать GRO/GSO/TSO на этом NIC без рисков?
# На некоторых virtio-net конфигурациях GRO+TSO ломает packet flow для XHTTP/Reality.
# Стратегия: если виртуализация openvz/lxc/docker — не трогаем offload вообще
# (всё равно контролируется хостом). На KVM/Xen — оставляем default настройки,
# но фиксируем `gro on` (важно для производительности) и `lro off` (важно для
# корректной работы прокси).
nic_offload_safe_for_iface() {
    local iface="$1"
    local virt
    virt=$(detect_virt 2>/dev/null)
    case "$virt" in
        openvz|lxc|docker) return 1 ;;
    esac
    [ -n "$iface" ] && [ -d "/sys/class/net/$iface" ] || return 1
    return 0
}

# ECMP детектор: возвращает 0 если сейчас есть несколько default-маршрутов
# на разных интерфейсах (multipath сценарий — имеет смысл включить
# fib_multipath_hash_policy=1).
has_ecmp() {
    local n
    n=$(ip -4 route show default 2>/dev/null | grep -c '^default')
    [ "$n" -ge 2 ]
}

# VPN-iface детектор (v8.3): возвращает 0 если есть UP-интерфейс с типичным
# VPN-именем (tun0, wg0, ppp0, tap0, gpd0, openvpn, ipsec0, и т.п.).
has_vpn_iface() {
    local iface
    for iface in /sys/class/net/*; do
        local name
        name=$(basename "$iface")
        case "$name" in
            tun*|tap*|wg*|ppp*|ipsec*|gpd*|nordlynx*|vpn*|wireguard*)
                # Считаем только UP-iface, чтобы зомби-туннели не тянули нас в VPN-режим.
                if [ -r "$iface/operstate" ] && grep -qE '^(up|unknown)$' "$iface/operstate" 2>/dev/null; then
                    return 0
                fi
                ;;
        esac
    done
    return 1
}

# Скорость основного физического интерфейса в Мбит/с (для масштабирования
# netdev_max_backlog/dev_weight). Возвращает 0 если детект не удался.
detect_link_speed_mbps() {
    local iface speed
    iface=$(ip -4 route show default 2>/dev/null | awk '/^default/{for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
    [ -z "$iface" ] && { echo 0; return; }
    if command -v ethtool >/dev/null 2>&1; then
        speed=$(ethtool "$iface" 2>/dev/null | awk '/Speed:/ {gsub(/Mb\/s/,"",$2); print $2; exit}')
    fi
    [ -z "$speed" ] || ! [[ "$speed" =~ ^[0-9]+$ ]] && speed=0
    echo "$speed"
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

    # Опционально — socat (нужен для prom-serve)
    apt-get install -y --no-install-recommends socat >/dev/null 2>&1 || true

    echo -e "${GREEN}[+] Базовые компоненты установлены.${NC}"
    echo -e "${YELLOW}[i] Опционально: curl-impersonate-safari даёт TLS/JA3 как у iOS.${NC}"
    echo -e "${YELLOW}    https://github.com/lwthiker/curl-impersonate (release binaries)${NC}"

    # IMPERSONATE: при флаге --impersonate автоматически качаем curl-impersonate.
    if [ "$IMPERSONATE" = "1" ]; then
        install_curl_impersonate
    fi

    _audit install "deps_installed=ok impersonate=${IMPERSONATE}"
    sleep 1
}

# Опциональная установка curl-impersonate (TLS/JA3-fingerprint реального Safari).
install_curl_impersonate() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) echo -e "${YELLOW}[!] curl-impersonate: не поддерживается архитектура $arch${NC}"; return 1 ;;
    esac
    if command -v curl-impersonate-safari >/dev/null 2>&1; then
        echo -e "${GRAY}[i] curl-impersonate уже установлен.${NC}"; return 0
    fi
    # Q5 fix v8.3: тянем latest tag вместо хардкоженного 0.6.1.
    # Если GitHub API недоступен — fallback на проверенную 0.6.1.
    local ver fallback_ver="0.6.1"
    ver=$(curl -fsSL --max-time 10 \
        https://api.github.com/repos/lwthiker/curl-impersonate/releases/latest 2>/dev/null \
        | awk -F'"' '/"tag_name":/ {print $4; exit}' | sed 's/^v//')
    if [ -z "$ver" ] || ! [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${GRAY}[i] GitHub API недоступен — используем fallback v${fallback_ver}${NC}"
        ver="$fallback_ver"
    fi
    local url="https://github.com/lwthiker/curl-impersonate/releases/download/v${ver}/curl-impersonate-v${ver}.${arch}-linux-gnu.tar.gz"
    local tmp
    tmp=$(mktemp -d /tmp/.curl_imp.XXXXXX)
    echo -e "${CYAN}[*] Качаем curl-impersonate v${ver} ${arch}...${NC}"
    if curl -fsSL "$url" -o "$tmp/curl-imp.tgz" 2>/dev/null; then
        tar xzf "$tmp/curl-imp.tgz" -C "$tmp" 2>/dev/null
        local bin
        bin=$(find "$tmp" -name 'curl-impersonate-safari' -type f 2>/dev/null | head -1)
        if [ -n "$bin" ] && [ -x "$bin" ]; then
            install -m 0755 "$bin" /usr/local/bin/curl-impersonate-safari
            echo -e "${GREEN}[+] /usr/local/bin/curl-impersonate-safari установлен.${NC}"
        else
            echo -e "${RED}[!] Не нашли curl-impersonate-safari в архиве.${NC}"
        fi
    else
        echo -e "${RED}[!] Не удалось скачать $url${NC}"
    fi
    rm -rf "$tmp"
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
    # vm.swappiness — оптимизировано для ZRAM (180 = prefer compressed swap-in
    # over page eviction; имеет смысл только когда ZRAM сконфигурирован).
    # v8.7: per-preset значения (proxy=30 latency-sensitive, web=60 moderate,
    # balanced=180 default ZRAM-friendly).
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
    # v8.7: на proxy preset избегаем ZRAM-swap (latency-sensitive: handshake-burst
    # + busy connection pool). swappiness=30 — практически не свопим страницы пока
    # не подходит к OOM.
    PRESET_SWAPPINESS=30
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
    # v8.7: на web preset допускаем умеренный swap (cached static content can
    # tolerate IO-latency). 60 — сбалансированно между memory pressure и performance.
    PRESET_SWAPPINESS=60
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
            # Offload-настройки только если nic_offload_safe_for_iface даёт зелёный свет
            # (KVM/Xen/native — да; openvz/lxc/docker — нет).
            if nic_offload_safe_for_iface "$iface"; then
                ethtool -K "$iface" rx on tx on sg on tso on gso on gro on lro off >/dev/null 2>&1 || true
                # UDP GRO/GSO (v8.3): даёт +2-3x throughput на QUIC/Hysteria/WireGuard на 5.18+ ядрах.
                # Часть драйверов рапортует об ошибке если не поддерживают — игнорим.
                ethtool -K "$iface" rx-udp-gro-forwarding on >/dev/null 2>&1 || true
                ethtool -K "$iface" tx-udp-segmentation on >/dev/null 2>&1 || true
            else
                # Контейнер: только LRO off (важно для прокси), остальное по-умолчанию
                ethtool -K "$iface" lro off >/dev/null 2>&1 || true
            fi

            # Ring buffers до железного максимума
            local ring_max_rx ring_max_tx
            ring_max_rx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^RX:/{print $2; exit}')
            ring_max_tx=$(ethtool -g "$iface" 2>/dev/null | awk '/Pre-set maximums:/{f=1;next} f && /^TX:/{print $2; exit}')
            if [ -n "$ring_max_rx" ] && [ -n "$ring_max_tx" ]; then
                ethtool -G "$iface" rx "$ring_max_rx" tx "$ring_max_tx" >/dev/null 2>&1 || true
            fi
            ethtool -C "$iface" adaptive-rx on adaptive-tx on >/dev/null 2>&1 || \
                ethtool -C "$iface" rx-usecs 8 tx-usecs 8 >/dev/null 2>&1 || true

            # v8.4 NIC enhancements (best-effort, ошибки игнорируются):
            #  - rx-flow-hash udp4/udp6 sdfn — RSS hash включает src/dst ports,
            #    иначе все QUIC-сессии с одной пары IP идут на одну очередь.
            #  - hw-tc-offload — TC-классы выполняются в железе на Mellanox/Intel
            #    800-series, экономит CPU.
            #  - gso-max-size 65536 — большие GSO-фреймы для virtio-net,
            #    снижают packet-rate в host kernel.
            #  - ntuple-filters — нужно для kernel-bypass правил RSS.
            if nic_offload_safe_for_iface "$iface"; then
                ethtool -N "$iface" rx-flow-hash udp4 sdfn >/dev/null 2>&1 || true
                ethtool -N "$iface" rx-flow-hash udp6 sdfn >/dev/null 2>&1 || true
                ethtool -N "$iface" rx-flow-hash tcp4 sdfn >/dev/null 2>&1 || true
                ethtool -N "$iface" rx-flow-hash tcp6 sdfn >/dev/null 2>&1 || true
                ethtool -K "$iface" hw-tc-offload on >/dev/null 2>&1 || true
                ethtool -K "$iface" ntuple on >/dev/null 2>&1 || true
                # gso-max-size требует Linux 5.18+ и драйверной поддержки
                ip link set dev "$iface" gso_max_size 65536 >/dev/null 2>&1 || true
                ip link set dev "$iface" gro_max_size 65536 >/dev/null 2>&1 || true
            fi
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

    # v8.5: KSM (Kernel Samepage Merging) — на VPS с одинаковыми образами
    # многим страницам сильно дубликаты, KSM их merge'ит, экономит RAM 5-15%.
    # Включаем только если виртуализация (KSM на bare-metal не несёт пользы,
    # ест CPU). Скорость merge — sleep_millisecs=200 (мягкий, default 20).
    local virt
    virt=$(detect_virt)
    # v8.5: KSM ставим только под preset=proxy в виртуализации.
    # На balanced/web KSM ест CPU непрерывным сканированием — это меняет default
    # apply behaviour (CONTRIBUTING #5). Прокси-нагрузки сами решают что 5-15%
    # экономия RAM выгоднее CPU-overhead.
    if [ "$PRESET_NAME" = "proxy" ]; then
        case "$virt" in
            kvm|xen|hyperv|microsoft|vmware)
                if sysfs_safe /sys/kernel/mm/ksm/run 1; then
                    _log OK "${GREEN}[+] KSM=on (sleep_millisecs=200)${NC}"
                    sysfs_safe /sys/kernel/mm/ksm/sleep_millisecs 200
                    sysfs_safe /sys/kernel/mm/ksm/pages_to_scan 1000
                fi
                ;;
        esac
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
    # v8.4: bpf_jit_enable — JIT для всех eBPF/XDP программ. Default=0 на многих
    # ядрах. JIT даёт 10-100x ускорение интерпретатора (нужен для XDP/cilium-style
    # фильтров, для нашего шум-генератора — нейтрально, но для будущих helpers — критично).
    sysctl_safe net.core.bpf_jit_enable 1
    # v8.4: bpf_jit_kallsyms=1 (отладка/perf), bpf_jit_harden=1 (анти-spectre v1) —
    # включаем оба, незначительный CPU-overhead, заметно лучше observability.
    sysctl_safe net.core.bpf_jit_kallsyms 1
    sysctl_safe net.core.bpf_jit_harden 1

    # v8.5: io_uring и scheduler tuning — ТОЛЬКО для preset=proxy.
    # Используем $PRESET_NAME (resolved preset из preset_balanced/proxy/web), а не
    # $PRESET (CLI arg, может быть пустой если preset загружен из файла).
    # CONTRIBUTING rule #5: default apply (balanced/web) не трогает security-sensitive
    # и latency-sensitive ядерные knob'ы.
    if [ "$PRESET_NAME" = "proxy" ]; then
        # io_uring — современный async-IO API. Default disabled на secure-конфигах
        # (Ubuntu 22.04+ disable=2 в LSM). Прокси (sing-box/h2o) умеют — +20-40% throughput.
        sysctl_safe kernel.io_uring_disabled 0
        # sched_min_granularity_ns=10ms (default 1.5ms) — больше CPU-time per task,
        # меньше context-switch overhead. На balanced/web ставить не нужно — они хотят
        # низкую latency, а 6.7x granularity её ухудшит.
        sysctl_safe kernel.sched_min_granularity_ns 10000000
        sysctl_safe kernel.sched_wakeup_granularity_ns 15000000
    fi

    # v8.6: numa_balancing — на не-NUMA-VPS (1 узел) автобаланс только сжигает CPU.
    # Auto-detect: если numactl сообщает 1 node, выключаем; если ≥2 — оставляем kernel default.
    # На bare-metal или multi-socket это критично оставить включённым (1).
    if command -v numactl >/dev/null 2>&1; then
        local _numa_nodes
        _numa_nodes=$(numactl --hardware 2>/dev/null | awk '/available:/{print $2}')
        if [ -n "$_numa_nodes" ] && [ "$_numa_nodes" = "1" ]; then
            sysctl_safe kernel.numa_balancing 0
        fi
    elif [ -d /sys/devices/system/node ]; then
        # Без numactl: считаем узлы через sysfs.
        local _node_count
        _node_count=$(find /sys/devices/system/node -maxdepth 1 -name 'node[0-9]*' 2>/dev/null | wc -l)
        [ "$_node_count" = "1" ] && sysctl_safe kernel.numa_balancing 0
    fi

    # v8.7 fix (Devin Review #10): v8.6 ошибочно ставил `udp_l3mdev_accept 0` с
    # комментарием про udp_hash_entries — это два разных параметра. udp_hash_entries
    # вообще не runtime-sysctl, а kernel boot-parameter (`udphash=N` / read-only
    # после boot). Удалили баговую строку; правильный l3mdev_accept=1 ставится
    # ниже в v8.7-блоке (вместе с tcp_l3mdev_accept).
    # busy_poll/busy_read=50 уже стоят выше — синхронизировано для UDP/QUIC.

    # v8.6: IPv6 privacy extensions (RFC 4941) — temp-addr как primary source-addr
    # для исходящих соединений. Имитирует поведение реального iOS (anti-tracking).
    # Гейтим под proxy — на balanced/web стабильный адрес важнее (rDNS, firewall
    # rules, monitoring). На proxy noise/stealth-исходящий трафик главнее.
    # Incoming SSH/VPN не затрагивается — listen socket bind'ится на любой адрес.
    if [ "$PRESET_NAME" = "proxy" ]; then
        sysctl_safe net.ipv6.conf.all.use_tempaddr 2
        sysctl_safe net.ipv6.conf.default.use_tempaddr 2
        sysctl_safe net.ipv6.conf.all.regen_max_retry 3
        # max_desync_factor — уменьшаем «случайный сдвиг» обновления temp-addr (default 600s).
        sysctl_safe net.ipv6.conf.all.max_desync_factor 60
    fi

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

    # UDP — критично для QUIC/Reality/XHTTP, а также WireGuard/OpenVPN/Hysteria2/TUIC.
    # Расширено в v8.3: per-socket min повышен (для серверов с тяжёлым QUIC),
    # optmem_max для SO_ZEROCOPY, и общий udp_mem (в страницах) под прокси-нагрузку.
    sysctl_safe net.ipv4.udp_rmem_min 131072
    sysctl_safe net.ipv4.udp_wmem_min 131072
    sysctl_safe net.ipv4.udp_mem "786432 1048576 1572864"
    # NB: net.core.optmem_max уже выставлен выше в 4194304 (4MB) — не перетираем.
    # TFO black-hole defuse (v8.3): дефолт ядра — 1ч лок после первой неудачи.
    # На флапающей сети это «тихая» причина почему TFO «не работает».
    sysctl_safe net.ipv4.tcp_fastopen_blackhole_timeout_sec 0

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
    # v8.4: shifted from 300s → 600s — стабильнее BBR-оценка при джиттере на
    # длинных линиях (РФ↔Европа), без потери adaptивности на мобильных.
    sysctl_safe net.ipv4.tcp_min_rtt_wlen 600
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
    # v8.6: tcp_thin_dupack=1 — gated to --preset proxy (CONTRIBUTING #5: tcp_thin_*).
    # Включает dupack-ускорение (1 dupack → fast retx, не 3) для streams помеченных
    # TCP_THIN_LINEAR_TIMEOUTS. На balanced/web preset не трогаем — там обычные потоки.
    if [ "$PRESET_NAME" = "proxy" ]; then
        sysctl_safe net.ipv4.tcp_thin_dupack 1
    fi
    # v8.6: tcp_reordering 6 → 10 — на jittery-облаках (RU↔EU, мобильные) spurious
    # retransmits заметно реже; max_reordering 300 → 600 — потолок для extreme cases.
    sysctl_safe net.ipv4.tcp_reordering 10
    sysctl_safe net.ipv4.tcp_max_reordering 600
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

    # Доводки v8.2 (PHOENIX-Z++):
    #  - tcp_rto_min_us — минимальный RTO в микросекундах (новое в 6.x). Уменьшает
    #    время до retransmit на jitter'ных РФ-облаках с ~30-80мс выигрышем на потерях.
    #  - tcp_comp_sack_delay_ns / tcp_comp_sack_nr — SACK compression уменьшает
    #    CPU на каждый ACK при множестве потерь (важно для MPTCP/sing-box).
    #  - tcp_comp_sack_slack_ns — допустимая задержка перед сжатием.
    #  - tcp_pingpong_thresh — порог переключения в pingpong mode (новое в 6.1+).
    #  - tcp_min_tso_segs / tcp_tso_win_divisor — балансируем TSO под прокси.
    #  - tcp_no_ssthresh_metrics_save — не сохраняем устаревший ssthresh между сессиями.
    sysctl_safe net.ipv4.tcp_rto_min_us 100000
    sysctl_safe net.ipv4.tcp_comp_sack_delay_ns 1000000
    sysctl_safe net.ipv4.tcp_comp_sack_nr 44
    sysctl_safe net.ipv4.tcp_comp_sack_slack_ns 100000
    sysctl_safe net.ipv4.tcp_min_tso_segs 2
    sysctl_safe net.ipv4.tcp_tso_win_divisor 3
    sysctl_safe net.ipv4.tcp_no_ssthresh_metrics_save 1
    sysctl_safe net.ipv4.tcp_pingpong_thresh 1

    # ECMP / multipath: если у VPS реально несколько default-маршрутов на разные
    # интерфейсы или включён --ecmp флаг, разрешаем мульти-путь по hash от L4-портов.
    if [ "$ECMP" = "1" ] || has_ecmp; then
        sysctl_safe net.ipv4.fib_multipath_use_neigh 1
        sysctl_safe net.ipv4.fib_multipath_hash_policy 1
    fi

    # high-order аллокатор страниц: разрешаем jumbo-skb на >10G линках.
    sysctl_safe net.core.high_order_alloc_disable 0

    # MPTCP (Linux 5.6+)
    if [ "$kvi" -ge 50600 ]; then
        sysctl_safe net.mptcp.enabled 1
    fi

    # Маскировка стека: TTL=64 как у нативного Linux-десктопа.
    sysctl_safe net.ipv4.ip_default_ttl 64

    # Security / hygiene.
    # rp_filter (v8.3): сохраняем backward-compat дефолт =1 (strict, как было в v8.2).
    # Loose mode (=2) включаем только под --vpn или при детекте VPN-iface, потому что
    # strict (=1) дропает asymmetric routing, что ломает WireGuard/OpenVPN/MPTCP.
    # Это поведение соответствует CONTRIBUTING.md: «no default change without opt-in».
    sysctl_safe net.ipv4.tcp_syncookies 1
    sysctl_safe net.ipv4.tcp_rfc1337 1
    local rp_filter_target=1
    if [ "$VPN_FORCE" = "1" ] || has_vpn_iface; then
        rp_filter_target=2
    fi
    sysctl_safe net.ipv4.conf.all.rp_filter "$rp_filter_target"
    sysctl_safe net.ipv4.conf.default.rp_filter "$rp_filter_target"
    sysctl_safe net.ipv4.conf.all.accept_redirects 0
    sysctl_safe net.ipv4.conf.default.accept_redirects 0
    sysctl_safe net.ipv4.conf.all.send_redirects 0
    sysctl_safe net.ipv4.conf.default.send_redirects 0
    sysctl_safe net.ipv4.conf.all.accept_source_route 0
    sysctl_safe net.ipv4.conf.default.accept_source_route 0
    sysctl_safe net.ipv4.icmp_echo_ignore_broadcasts 1
    sysctl_safe net.ipv6.conf.all.accept_redirects 0
    sysctl_safe net.ipv6.conf.default.accept_redirects 0
    sysctl_safe net.ipv6.conf.all.accept_source_route 0
    sysctl_safe net.ipv6.conf.default.accept_source_route 0

    # IPv6 mirror
    sysctl_safe net.ipv6.conf.all.disable_ipv6 0
    sysctl_safe net.ipv6.conf.default.disable_ipv6 0

    # VPN-friendly доводки: включаются если виден tun*/wg*/ppp*/tap* iface
    # (т.е. на машине уже поднят VPN-туннель) или передан явный --vpn.
    if [ "$VPN_FORCE" = "1" ] || has_vpn_iface; then
        sysctl_safe net.ipv4.conf.all.accept_local 1
        sysctl_safe net.ipv4.ip_forward 1
        sysctl_safe net.ipv6.conf.all.forwarding 1
        # На VPN-сервере conntrack-помощники (FTP/SIP/IRC NAT) лучше выключить —
        # они могут потеряться через туннель и привести к странным дропам.
        sysctl_safe net.netfilter.nf_conntrack_helper 0
    fi

    # IPv6 параллель ключевых TCP knob'ов (v8.3): TCP-стек у v4 и v6 общий, но
    # часть control-knob'ов имеет per-family версию.
    sysctl_safe net.ipv6.bindv6only 0

    # tcp_keepalive_intvl/probes уже выставлены выше (одинаково для всех пресетов).

    # netdev_max_backlog масштабируем под скорость линка: на 25G+ дефолт мал.
    # ВАЖНО (v8.3 fix): берём max(preset, auto-scale), чтобы не понижать значения
    # пресетов (например proxy=1000000) на 1G-VPS до 30000.
    local link_speed_mbps backlog_target dev_weight_target backlog_eff dev_weight_eff
    link_speed_mbps=$(detect_link_speed_mbps)
    if [ "$link_speed_mbps" -ge 25000 ]; then
        backlog_target=300000
        dev_weight_target=256   # v8.7: 25G+ NIC — больше weight для big napi-poll cycles
    elif [ "$link_speed_mbps" -ge 10000 ]; then
        backlog_target=100000
        dev_weight_target=192   # v8.7: было 96, теперь 192 — на 10G дефолт мал
    else
        backlog_target=30000
        dev_weight_target=64
    fi
    backlog_eff="$PRESET_NETDEV_BACKLOG"
    [ "$backlog_target" -gt "$backlog_eff" ] && backlog_eff="$backlog_target"
    # dev_weight: уже выставлен 128 в base apply (line 965). Берём максимум.
    dev_weight_eff=128
    [ "$dev_weight_target" -gt "$dev_weight_eff" ] && dev_weight_eff="$dev_weight_target"
    sysctl_safe net.core.netdev_max_backlog "$backlog_eff"
    sysctl_safe net.core.dev_weight "$dev_weight_eff"

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
        # v8.4: tcp_be_liberal — не дропаем TCP-сегменты с «странным» seq,
        # типичная проблема под ASN-roaming / mobile-NAT и асимметричной маршрутизацией.
        # Не открывает уязвимостей: conntrack продолжает следить за state, просто терпимее.
        sysctl_safe net.netfilter.nf_conntrack_tcp_be_liberal 1
    fi

    # VM / ZRAM tuning
    sysctl_safe vm.swappiness "$PRESET_SWAPPINESS"
    sysctl_safe vm.page-cluster 0
    sysctl_safe vm.vfs_cache_pressure 50
    sysctl_safe vm.dirty_background_ratio 3
    sysctl_safe vm.dirty_ratio 10
    sysctl_safe vm.dirty_writeback_centisecs 500
    sysctl_safe vm.dirty_expire_centisecs 1500
    # v8.4: vm.min_free_kbytes — поднимаем под размер RAM (~0.5%), но min 64MB,
    # max 1GB. Иначе под burst (тысячи TLS-handshake'ов) kswapd не успевает,
    # начинаются direct-reclaim'ы, latency-spike'и или OOM. На VPS 1GB RAM
    # default ~22MB — катастрофически мало для прокси-нагрузки.
    local min_free_target
    min_free_target=$(( mem_mb * 1024 / 200 ))   # 0.5% RAM в kB
    [ "$min_free_target" -lt 65536 ] && min_free_target=65536
    [ "$min_free_target" -gt 1048576 ] && min_free_target=1048576
    sysctl_safe vm.min_free_kbytes "$min_free_target"
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
    # v8.6: kernel.numa_balancing — больше не выставляем безусловно, теперь только
    # на 1-NUMA-узловых VPS (auto-detect вверху, ~line 1447). На multi-socket
    # bare-metal оставляем включённым, иначе теряем balanced placement.
    sysctl_safe kernel.timer_migration 1

    # v8.7: VRF / l3mdev support — для cilium-style сред и dual-WAN setup'ов
    # (когда VRF используется как изоляция). Безопасно везде: kernel молча
    # игнорирует если l3mdev/VRF не используется.
    sysctl_safe net.ipv4.tcp_l3mdev_accept 1
    sysctl_safe net.ipv4.udp_l3mdev_accept 1

    # v8.7: net.unix.max_dgram_qlen — для прокси с unix-socket интерконнекта
    # (sing-box ↔ haproxy ↔ envoy через /run/*.sock). Default 10 — мал на любом
    # busy-прокси, рекомендация 512.
    sysctl_safe net.unix.max_dgram_qlen 512

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
        echo "# === VPS Optimizer v8.2 PHOENIX-Z++ ==="
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

# v8.4: initcwnd via `ip route` — Google ставит 30, мы тоже. На дефолтном
# маршруте даёт ~3-4х данных в первом RTT (десятки KB вместо ~14KB при cwnd=10).
# Не персистентно (живёт до перезагрузки), но apply переустанавливает.
apply_route_initcwnd() {
    [ "$DRY_RUN" = "1" ] && return 0
    local def_line def_iface def_via
    def_line=$(ip -4 route show default 2>/dev/null | head -1)
    [ -z "$def_line" ] && return 0
    def_iface=$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$def_line")
    def_via=$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$def_line")
    [ -z "$def_iface" ] && return 0
    # Пропускаем VPN-iface — там initcwnd не имеет смысла, а route change может
    # перетереть ту, что VPN-приложение само поставило.
    case "$def_iface" in
        tun*|tap*|wg*|ppp*|ipsec*) return 0 ;;
    esac
    local change_args=(default dev "$def_iface" initcwnd 30 initrwnd 30)
    [ -n "$def_via" ] && change_args=(default via "$def_via" dev "$def_iface" initcwnd 30 initrwnd 30)
    if ip route change "${change_args[@]}" >/dev/null 2>&1; then
        _log OK "  route initcwnd=30 / initrwnd=30 на ${def_iface}"
    fi
}

# v8.4: kernel TLS (kTLS). modprobe tls — даёт ядру способность делать sendfile()
# на TLS-сокетах (zero-copy). Прирост -30-50% CPU на TLS-heavy нагрузках,
# если приложение умеет (nginx со сборкой `--with-openssl-opt=enable-ktls`).
# Сам `modprobe tls` безопасен: не меняет поведения других сокетов.
apply_ktls_module() {
    [ "$DRY_RUN" = "1" ] && return 0
    modprobe tls 2>/dev/null && _log OK "  kTLS module loaded (sendfile-on-TLS available)"
}

# v8.4: OOM hint — если на машине крутятся проксильки (xray/sing-box/hysteria/v2ray),
# ставим им oom_score_adj=-500 (но не -1000, т.к. это «никогда не убивать» —
# опасно если процесс утекает память). Отрицательное значение = реже убивает,
# чем других. Без --force ничего не делаем для незнакомых процессов.
apply_oom_hints() {
    [ "$DRY_RUN" = "1" ] && return 0
    local proc pids p
    for proc in xray sing-box hysteria hysteria2 v2ray tuic-server wireguard-go; do
        if ! command -v pgrep >/dev/null 2>&1; then
            return 0
        fi
        pids=$(pgrep -x "$proc" 2>/dev/null)
        for p in $pids; do
            if [ -w "/proc/$p/oom_score_adj" ]; then
                echo -500 > "/proc/$p/oom_score_adj" 2>/dev/null && \
                    _log OK "  OOM-protect $proc (pid=$p) → score_adj=-500"
            fi
        done
    done
}

apply_optimizations() {
    [ "$DRY_RUN" = "1" ] && _log INFO "${YELLOW}[i] DRY-RUN: ничего не записывается на диск.${NC}"
    if [ "$LEARN_MODE" = "1" ]; then
        _log INFO "${CYAN}$(_t learn_header)${NC}"
        _log INFO "${GRAY}    each sysctl_safe / sysfs_safe call will print: current → desired (rationale).${NC}"
    fi
    _log INFO "${YELLOW}[*] Глобальный тюнинг v${SCRIPT_VERSION} PHOENIX-Z++...${NC}"

    if ! acquire_lock; then
        return "$EXIT_LOCK_BUSY"
    fi

    # Internet-check: если связи нет — предупреждаем (но не блокируем,
    # пользователь может специально применять оффлайн).
    if [ "$DRY_RUN" != "1" ] && ! check_internet; then
        _log WARN "${YELLOW}[!] Нет интернета — продолжаем, но some checks могут не пройти.${NC}"
    fi

    VIRT=$(detect_virt)
    PROVIDER=$(detect_provider)
    _log INFO "  Virt:     $VIRT"
    _log INFO "  Provider: $PROVIDER"

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

    # B3: rollback-snapshot перед apply (только если не dry-run и не уже существует
    # snapshot за последние 60 секунд — чтобы не флудить при повторных apply).
    # v8.3 (L4): дополнительно поддерживаем daily-rotation — один daily-snapshot
    # за сутки, держим 7 штук. Pre-apply снапшоты держим максимум 30 штук.
    if [ "$DRY_RUN" != "1" ]; then
        mkdir -p "$SNAPSHOT_DIR" 2>/dev/null || true
        local last_snap
        last_snap=$(find "$SNAPSHOT_DIR" -maxdepth 1 -name 'pre-apply-*.tar.gz' -mmin -1 2>/dev/null | head -1)
        if [ -z "$last_snap" ]; then
            local snap_file
            snap_file="$SNAPSHOT_DIR/pre-apply-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
            tar -czf "$snap_file" \
                --ignore-failed-read \
                "$SYSCTL_CONF" "$LIMITS_CONF" "$DNS_CONF" "$DNS_STATE" \
                "$NOISE_CONF" "$PRESET_FILE" 2>/dev/null || true
            _log INFO "  Snapshot: $snap_file"
        fi
        # Daily snapshot (v8.3): максимум 1 в сутки.
        local daily_file
        daily_file="$SNAPSHOT_DIR/daily-$(date -u +%Y%m%d).tar.gz"
        if [ ! -f "$daily_file" ]; then
            tar -czf "$daily_file" \
                --ignore-failed-read \
                "$SYSCTL_CONF" "$LIMITS_CONF" "$DNS_CONF" "$DNS_STATE" \
                "$NOISE_CONF" "$PRESET_FILE" 2>/dev/null || true
        fi
        # Ротация: pre-apply max 30, daily max 7.
        # shellcheck disable=SC2012  # ls -t достаточно для имён вида pre-apply-*.tar.gz
        ls -1t "$SNAPSHOT_DIR"/pre-apply-*.tar.gz 2>/dev/null | tail -n +31 | xargs -r rm -f
        # shellcheck disable=SC2012
        ls -1t "$SNAPSHOT_DIR"/daily-*.tar.gz 2>/dev/null | tail -n +8 | xargs -r rm -f
    fi

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
    apply_route_initcwnd
    apply_ktls_module
    apply_oom_hints

    # B1: idempotency — если новый sysctl-файл побитово совпадает с уже существующим,
    # пропускаем перезапись и `sysctl -p` (всё уже применено).
    if [ "$DRY_RUN" != "1" ] && [ -f "$SYSCTL_CONF" ] && [ -s "$SYSCTL_TMP" ]; then
        local new_hash old_hash
        new_hash=$(awk 'NF && !/^#/' "$SYSCTL_TMP" 2>/dev/null | sort -u | sha256sum | awk '{print $1}')
        old_hash=$(awk 'NF && !/^#/' "$SYSCTL_CONF" 2>/dev/null | sort -u | sha256sum | awk '{print $1}')
        if [ -n "$new_hash" ] && [ "$new_hash" = "$old_hash" ]; then
            _log INFO "${GRAY}[i] sysctl-конфиг не изменился — пропускаем перезапись.${NC}"
        else
            finalize_sysctl_conf
        fi
    else
        finalize_sysctl_conf
    fi

    self_test

    _log OK "${GREEN}[+] Phoenix-Z++ v${SCRIPT_VERSION}: BBR=${APPLIED_BBR}, qdisc=${APPLIED_QDISC}, preset=${PRESET_NAME}, provider=${PROVIDER}.${NC}"
    _audit apply "preset=${PRESET_NAME} virt=${VIRT} provider=${PROVIDER} bbr=${APPLIED_BBR} qdisc=${APPLIED_QDISC} dry_run=${DRY_RUN}"
    rm -f "$SYSCTL_TMP"; trap - EXIT
    release_lock

    if [ "$LEARN_MODE" = "1" ]; then
        _log INFO "${CYAN}$(_t learn_footer)${NC}"
    fi

    # Auto-rollback (v8.3, L1): если после apply связь потерялась — откатываемся.
    # Безопасная сетка: NO_ROLLBACK=1 или DRY_RUN=1 пропускают проверку.
    # Не блокирует SSH: проверка короткая (max ~5 сек), затем мгновенный откат
    # на pre-apply snapshot.
    if [ "$DRY_RUN" != "1" ] && [ "$NO_ROLLBACK" != "1" ]; then
        if ! post_apply_connectivity_ok; then
            _log WARN "${RED}[!] После apply связь не отвечает — откатываемся на pre-apply snapshot.${NC}"
            _audit apply "auto_rollback triggered=connectivity_lost"
            rollback_last_snapshot
            return "$EXIT_ROLLED_BACK"
        fi
    fi

    [ "$QUIET" = "1" ] && return 0
    [ "$CLI_MODE" = "1" ] && return 0
    [ -t 0 ] && read -r -p "Нажмите Enter..."
    return 0
}

# Post-apply connectivity probe (v8.3): проверяем DNS + TCP-handshake, не ICMP.
# ICMP может быть отфильтрован в облаках, но если TCP/443 + DNS работают —
# пользователь точно не лишился SSH (та же таблица маршрутизации).
post_apply_connectivity_ok() {
    local probes_ok=0
    # DNS lookup через системный resolver (быстрее ping'a и проверяет полную цепочку)
    if getent hosts cloudflare.com >/dev/null 2>&1; then
        probes_ok=$((probes_ok + 1))
    elif getent hosts 1.1.1.1 >/dev/null 2>&1; then
        probes_ok=$((probes_ok + 1))
    fi
    # TCP handshake до 1.1.1.1:443 (timeout 3s).
    if command -v timeout >/dev/null 2>&1; then
        if timeout 3 bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null; then
            probes_ok=$((probes_ok + 1))
        fi
    else
        # Без timeout — короткий nc.
        if command -v nc >/dev/null 2>&1 && nc -z -w 3 1.1.1.1 443 2>/dev/null; then
            probes_ok=$((probes_ok + 1))
        fi
    fi
    # Хоть одна из проб ок — считаем что связь есть.
    [ "$probes_ok" -ge 1 ]
}

# Откат на самый свежий pre-apply snapshot (v8.3).
# Тихо игнорирует если snapshot'ов нет (например первый apply).
rollback_last_snapshot() {
    local last_snap
    last_snap=$(find "$SNAPSHOT_DIR" -maxdepth 1 -name 'pre-apply-*.tar.gz' 2>/dev/null | sort | tail -1)
    if [ -z "$last_snap" ]; then
        _log WARN "${YELLOW}[!] Snapshot'ов нет — откат невозможен. Ручной reset рекомендован.${NC}"
        return 1
    fi
    _log INFO "  Восстанавливаем: $last_snap"
    tar -xzf "$last_snap" -C / 2>/dev/null || true
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
    return 0
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
ENABLE_PUSH=1             # v8.4: ротация APNs / FCM / WNS push-keepalive
ENABLE_STUN=1             # v8.4: WebRTC STUN UDP бёрсты (Google/Cloudflare)
ENABLE_WEBSOCKET=1        # v8.4: длинные TCP/443 keepalive (Telegram/Discord-like)
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

# === Время-зависимый профиль «места» (новое в v8.2) ===
# auto      — стандартная кривая дня (как было)
# office    — активность 9-18, тишина в остальное время (рабочая VPS)
# home      — пик 19-23, лёгкая утренняя проверка (домашняя VPS)
# always_on — равномерно 24/7 (для серверов «без хозяина»)
PLACE_PROFILE=auto

# === Cloud / NTP / cloud-init phantoms (новое в v8.2) ===
# Реальная Ubuntu всегда тянет NTP/apt/snapcraft в фоне. Включает фоновые
# запросы к archive.ubuntu.com, security.ubuntu.com, time.ubuntu.com,
# api.snapcraft.io. Без этого профиль «слишком чистый» и подозрительный.
ENABLE_CLOUD_PHANTOM=1
CLOUD_PHANTOM_INTERVAL_MIN=30
CLOUD_PHANTOM_INTERVAL_MAX=180

# === DNS prefetch (новое в v8.2) ===
# Имитирует браузерный DNS-preconnect — тихо резолвит host'ы заранее.
# Без HTTP, только DNS-запрос — попадает в логи провайдера как обычный
# браузерный preconnect.
ENABLE_DNS_PREFETCH=1
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
ENABLE_PUSH=${ENABLE_PUSH:-1}
ENABLE_STUN=${ENABLE_STUN:-1}
ENABLE_WEBSOCKET=${ENABLE_WEBSOCKET:-1}
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
# v8.7: iOS 18 — Apple Maps tile-сервера (gsp-ssl), iMessage relay, Apple Music
# API, Spotlight Suggest, Siri/Smoot endpoints. Реальный iPhone обращается к ним
# постоянно: Maps prefetch, Push, Music feed, Search suggestions, Siri WebKit-cards.
"https://gsp-ssl.ls.apple.com/" "https://gsp10-ssl.ls.apple.com/"
"https://gspe35-ssl.ls.apple.com/" "https://apzones.apple.com/"
"https://api.apple-mapkit.com/v1/" "https://maps-api.apple.com/v1/"
"https://relay.smoot.apple.com/" "https://smoot.apple.com/"
"https://smoot-search.apple.com/" "https://api-glb-aze.smoot.apple.com/"
"https://amp-api.music.apple.com/v1/" "https://music.apple.com/"
"https://itunes.apple.com/" "https://radio.apple.com/"
"https://guzzoni.apple.com/" "https://guzzoni-apple-com.akadns.net/"
"https://siri-search.apple.com/" "https://amp-api-edge.apple.com/"
"https://content.icloud.com/" "https://p104-content.icloud.com/"
"https://p104-fmip.icloud.com/" "https://p104-mailws.icloud.com/"
"https://p104-keyvalueservice.icloud.com/" "https://p104-imws.icloud.com/"
)
URLS_CAPTIVE=(
"https://captive.apple.com/hotspot-detect.html"
"https://www.apple.com/library/test/success.html"
"https://gsp64-ssl.ls.apple.com/"
# v8.7: реальный iPhone делает hotspot-detect каждые ~60s после Wi-Fi-attach
# и периодически в фоне; полезно повторять чтобы соответствовать profile.
"https://www.apple.com/library/test/success.html?cb=1"
"https://www.apple.com/library/test/success.html?cb=2"
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

# Per-session referer (имитирует браузерную навигационную цепочку:
# главная → статья → статья → ... — тот же session, тот же Referer).
declare -A LAST_URL_PER_TAG
declare -A ETAG_PER_URL
declare -A LASTMOD_PER_URL

# Health-state — пишется в /run/vps-noise/health.json для status-команды.
HEALTH_FILE_NOISE="/run/vps-noise/health.json"
mkdir -p "$(dirname "$HEALTH_FILE_NOISE")" 2>/dev/null || true
NOISE_REQ_TOTAL=0
NOISE_REQ_OK=0
NOISE_REQ_ERR=0
NOISE_LAST_TS=0
START_TS=$(date +%s)
update_health() {
    [ -w "$(dirname "$HEALTH_FILE_NOISE")" ] || return 0
    cat > "$HEALTH_FILE_NOISE" 2>/dev/null <<HJEOF
{
  "last_request_ts": $NOISE_LAST_TS,
  "requests_total": $NOISE_REQ_TOTAL,
  "requests_ok": $NOISE_REQ_OK,
  "requests_error": $NOISE_REQ_ERR,
  "pid": $$,
  "started_at": $START_TS
}
HJEOF
}

# /dev/urandom-based случайное число (для параллельных loops без коллизий)
urand() {
    local lo="$1" hi="$2" span r
    span=$(( hi - lo + 1 ))
    [ "$span" -le 0 ] && { echo "$lo"; return; }
    r=$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' ')
    [ -z "$r" ] && r=$RANDOM
    echo $(( r % span + lo ))
}

# Случайное число в диапазоне [a, b] — теперь через /dev/urandom.
rrange() { urand "$1" "$2"; }

# Случайный rate-limit
rand_rate() { urand "$RATE_KB_MIN" "$RATE_KB_MAX"; }

# Извлечь схему+host (https://example.com) — для Sec-Fetch-Site и Referer cross-site детекции.
url_origin() {
    echo "$1" | awk -F/ '{print $1"//"$3}'
}

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

    # Referer chain: если в этой сессии уже был запрос, делаем Referer.
    # Sec-Fetch-Site вычисляется как same-origin / cross-site / none.
    local prev="${LAST_URL_PER_TAG[$tag]:-}"
    local sec_fetch_site="none"
    local referer_arg=()
    if [ -n "$prev" ] && [ "$prev" != "$url" ]; then
        referer_arg=(-H "Referer: $prev")
        if [ "$(url_origin "$prev")" = "$(url_origin "$url")" ]; then
            sec_fetch_site="same-origin"
        else
            sec_fetch_site="cross-site"
        fi
    fi

    # Cache headers: если у нас уже есть ETag/Last-Modified для этого URL, отправляем их.
    local cache_args=()
    if [ -n "${ETAG_PER_URL[$url]:-}" ]; then
        cache_args+=(-H "If-None-Match: ${ETAG_PER_URL[$url]}")
    fi
    if [ -n "${LASTMOD_PER_URL[$url]:-}" ]; then
        cache_args+=(-H "If-Modified-Since: ${LASTMOD_PER_URL[$url]}")
    fi

    local rate
    rate=$(rand_rate)

    # Дамп заголовков ответа во временный файл для парсинга ETag/Last-Modified.
    local hdr_tmp
    hdr_tmp=$(mktemp /tmp/.vps_noise_hdr.XXXXXX 2>/dev/null) || hdr_tmp="/dev/null"

    local args=(
        -s -o /dev/null
        --max-time 25 --connect-timeout 8
        --tls-max 1.3 --tlsv1.2
        --compressed
        --cookie-jar "$jar" --cookie "$jar"
        -A "$ua"
        -D "$hdr_tmp"
        -H "Accept: $ACCEPT"
        -H "Accept-Language: $accept_lang"
        -H "Accept-Encoding: $ACCEPT_ENC"
        -H "Sec-Fetch-Dest: document"
        -H "Sec-Fetch-Mode: navigate"
        -H "Sec-Fetch-Site: $sec_fetch_site"
        -H "Sec-Fetch-User: ?1"
        -H "Upgrade-Insecure-Requests: 1"
        -H "Priority: u=0, i"
        -H "DNT: 1"
        --limit-rate "${rate}K"
    )
    args+=("${referer_arg[@]}")
    args+=("${cache_args[@]}")
    if [ "$CURL_BIN" = "curl" ]; then
        # v8.4: Safari/Chrome ходят h3 ~50% когда сервер поддерживает,
        # а у нас было 1/3. Бампим до 1/2.
        if (( $(urand 0 1) == 0 )) && curl --help all 2>/dev/null | grep -q -- '--http3'; then
            args+=(--http3)
        else
            args+=(--http2)
        fi
        # v8.4: TLS 1.3 0-RTT / Early Data — Safari делает на resumed sessions.
        # curl поддерживает с 7.79+. Если не поддерживается — флаг проигнорится.
        if curl --help all 2>/dev/null | grep -q -- '--tls-earlydata'; then
            (( $(urand 0 2) == 0 )) && args+=(--tls-earlydata)
        fi
        # v8.6: iOS 18 — TCP_FASTOPEN_CONNECT. Реальный Safari ставит TFO_CONNECT
        # практически на каждый исходящий TCP-сокет (с момента iOS 9). У нас был
        # TFO в sysctl, но в curl-вызовах не использовали. curl 7.49+ умеет --tcp-fastopen.
        # Безопасно: server поддержи нет → fallback к стандартному 3WHS.
        # На Linux SO_NOSIGPIPE недоступен, но curl делает MSG_NOSIGNAL — equivalent.
        if curl --help all 2>/dev/null | grep -q -- '--tcp-fastopen'; then
            (( $(urand 0 1) == 0 )) && args+=(--tcp-fastopen)
        fi
    fi

    NOISE_REQ_TOTAL=$(( NOISE_REQ_TOTAL + 1 ))
    NOISE_LAST_TS=$(date +%s)
    if "$CURL_BIN" "${args[@]}" "$url" 2>/dev/null; then
        NOISE_REQ_OK=$(( NOISE_REQ_OK + 1 ))
    else
        NOISE_REQ_ERR=$(( NOISE_REQ_ERR + 1 ))
    fi
    update_health

    # Cache headers: парсим из ответа (берём чистые значения).
    if [ -f "$hdr_tmp" ]; then
        local etag lastmod
        etag=$(awk -F': ' 'tolower($1)=="etag"{sub(/\r$/,"",$2); print $2; exit}' "$hdr_tmp" 2>/dev/null)
        lastmod=$(awk -F': ' 'tolower($1)=="last-modified"{sub(/\r$/,"",$2); print $2; exit}' "$hdr_tmp" 2>/dev/null)
        [ -n "$etag" ]    && ETAG_PER_URL[$url]="$etag"
        [ -n "$lastmod" ] && LASTMOD_PER_URL[$url]="$lastmod"
        rm -f "$hdr_tmp"
    fi

    LAST_URL_PER_TAG[$tag]="$url"
}

# ===== DNS prefetch — имитация браузерного DNS preconnect =====
# Реальный браузер всегда резолвит host'ы заранее. Делаем дополнительный
# trace через `getent` чтобы попасть в DNS-логи провайдера.
dns_prefetch() {
    local host
    host=$(echo "$1" | awk -F/ '{print $3}')
    [ -n "$host" ] && getent hosts "$host" >/dev/null 2>&1 || true
}

# ===== Cloud / NTP / metadata phantoms =====
# Реальная Ubuntu периодически тянет NTP и cloud-init metadata. Ставим эти
# запросы рандомно, чтобы trace выглядел нативно.
cloud_phantom() {
    local choice=$(( $(urand 0 99) ))
    if (( choice < 40 )); then
        # NTP запрос (UDP 123)
        timeout 3 bash -c 'exec 3<>/dev/udp/time.ubuntu.com/123 && echo -ne "\x1b\x00\x00\x00" >&3 && sleep 0.5' 2>/dev/null || true
    elif (( choice < 70 )); then
        # apt-метаданные
        http_request "http://archive.ubuntu.com/ubuntu/dists/noble/Release" desktop en cloud_phantom
    elif (( choice < 90 )); then
        # security-апдейты
        http_request "http://security.ubuntu.com/ubuntu/dists/noble-security/Release" desktop en cloud_phantom
    else
        # snap refresh (просто HEAD без install)
        http_request "https://api.snapcraft.io/v2/snaps/info/core24" desktop en cloud_phantom
    fi
}

# ===== APNs keepalive =====
apns_keepalive() {
    timeout 6 bash -c 'exec 3<>/dev/tcp/courier.push.apple.com/5223 && sleep 3' 2>/dev/null || true
}

# ===== FCM / Microsoft / Apple push keepalive (v8.4) =====
# Реальные мобильные устройства (Android, Win, Mac) держат TCP до push-сервисов
# **постоянно**, периодически слегка «дёргают» соединение. Чисто TCP-handshake +
# короткое ожидание. Никаких HTTP-запросов, никаких данных в /dev/null.
# FCM_HOSTS перечисляет несколько endpoint'ов — алгоритм случайно выбирает один.
push_keepalive() {
    local hosts=(
        "courier.push.apple.com:5223"     # APNs (Apple)
        "1-courier.push.apple.com:5223"
        "2-courier.push.apple.com:5223"
        "mtalk.google.com:5228"           # FCM (Android / Chrome)
        "mtalk4.google.com:5228"
        "mtalk-staging.google.com:5228"
        "db5p.notify.windows.com:443"     # WNS (Windows)
        "vap04.notify.windows.com:443"
    )
    local pick="${hosts[$(urand 0 $(( ${#hosts[@]} - 1 )) )]}"
    local h="${pick%:*}" p="${pick##*:}"
    timeout 6 bash -c "exec 3<>/dev/tcp/$h/$p && sleep 3" 2>/dev/null || true
}

# ===== STUN UDP burst (v8.4) =====
# Браузеры/приложения регулярно делают WebRTC discovery: маленький UDP-пакет
# к публичному STUN серверу, ответ ~32-60 байт. Имитируем через bash UDP socket.
# Рассылаем 1-3 STUN Binding Request'а к рандомным STUN-серверам.
stun_burst() {
    # Сырой STUN Binding Request: 20 байт.
    # 0x0001 (Binding Request) + 0x0000 (length=0) + 0x2112A442 (magic cookie) +
    # 12-байтовый transaction ID. Собираем как `\xNN`-escape-строку (а не сырыми
    # байтами через $'...'), потому что bash-строки не могут содержать NUL —
    # любая `\x00` в \$'…' усекает переменную в 0 длины. printf %b развернёт.
    local stun_pkt='\x00\x01\x00\x00\x21\x12\xa4\x42'
    local b
    for ((b=0; b<12; b++)); do
        stun_pkt+=$(printf '\\x%02x' "$(urand 0 255)")
    done
    local stuns=(
        "stun.l.google.com:19302"
        "stun1.l.google.com:19302"
        "stun2.l.google.com:19302"
        "stun.cloudflare.com:3478"
        "stun.nextcloud.com:443"
    )
    local n i pick h p
    n=$(rrange 1 3)
    for ((i=0; i<n; i++)); do
        pick="${stuns[$(urand 0 $(( ${#stuns[@]} - 1 )) )]}"
        h="${pick%:*}" p="${pick##*:}"
        timeout 2 bash -c "
            exec 3<>/dev/udp/$h/$p
            printf '%b' '$stun_pkt' >&3
            head -c 64 <&3 >/dev/null 2>&1 &
            sleep 0.5
            kill %1 2>/dev/null
        " 2>/dev/null || true
        sleep "$(rrange 1 4)"
    done
}

# ===== WebSocket-style long-poll (v8.4) =====
# Реальные приложения (Telegram, Discord, IM в браузере, Push) держат TCP/443
# до сервиса 5-30+ минут с маленьким heartbeat'ом. У нас всё было request/response.
# Здесь — открыть TCP/443 к https-эндпоинту, дёрнуть HEAD, ждать молча 5-15 мин.
# Не нагружаем ничего: bash-сокет тратит ~12KB RAM, никаких HTTP-запросов внутри.
websocket_keepalive() {
    local hosts=(
        "edge-mqtt.facebook.com"
        "graph.facebook.com"
        "www.cloudflare.com"
        "icloud.com"
        "apple.com"
        "yandex.ru"
        "vk.com"
    )
    local h="${hosts[$(urand 0 $(( ${#hosts[@]} - 1 )) )]}"
    local secs
    secs=$(rrange 300 1200)   # 5-20 мин
    timeout "$secs" bash -c "exec 3<>/dev/tcp/$h/443 && sleep $secs" 2>/dev/null || true
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

# ===== Профиль времени суток + «места» (множитель пауз) =====
# PLACE_PROFILE: office (9-18 быстрые бёрсты), home (19-23 ютуб/новости),
# auto — по часам.
# Возвращает целочисленный множитель (в процентах) к базовому интервалу.
hour_factor() {
    local h profile="${PLACE_PROFILE:-auto}"
    h=$(date +%H); h=$((10#$h))
    case "$profile" in
        office)
            # «офис» — активность 9-18, минимальная остальное время
            if (( h >= 9 && h <= 18 )); then echo 60
            elif (( h >= NIGHT_HOUR_FROM && h <= NIGHT_HOUR_TO )); then echo 350
            else echo 200; fi
            return ;;
        home)
            # «дом» — пик вечером, лёгкая утренняя проверка
            if (( h >= 19 && h <= 23 )); then echo 60
            elif (( h >= 7 && h <= 9 )); then echo 80
            elif (( h >= NIGHT_HOUR_FROM && h <= NIGHT_HOUR_TO )); then echo 300
            else echo 130; fi
            return ;;
        always_on)
            # 24/7 (сервер)
            echo 100; return ;;
    esac
    # auto (default): кривая дня
    if (( h >= NIGHT_HOUR_FROM && h <= NIGHT_HOUR_TO )); then
        echo 250
    elif (( h >= PEAK_MORNING_FROM && h <= PEAK_MORNING_TO )); then
        echo 60
    elif (( h >= PEAK_EVENING_FROM && h <= PEAK_EVENING_TO )); then
        echo 70
    else
        echo 100
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
# v8.4: push_keepalive — APNs/FCM/WNS rotation
loop_push() {
    while true; do
        vacation_check_and_sleep
        push_keepalive
        sleep "$(rrange 600 1800)"    # 10-30 мин
    done
}
# v8.4: STUN UDP бёрсты — WebRTC-style discovery (Safari/Chrome делают регулярно)
loop_stun() {
    while true; do
        sleep "$(rrange 600 2400)"    # 10-40 мин
        vacation_check_and_sleep
        stun_burst
    done
}
# v8.4: websocket-like long-poll
loop_ws() {
    while true; do
        sleep "$(rrange 60 600)"      # 1-10 мин между сессиями
        vacation_check_and_sleep
        websocket_keepalive
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

# Cloud / NTP / metadata phantom — реальная Ubuntu всегда тянет эти эндпоинты в фоне.
loop_cloud() {
    while true; do
        sleep_minutes "${CLOUD_PHANTOM_INTERVAL_MIN:-30}" "${CLOUD_PHANTOM_INTERVAL_MAX:-180}"
        vacation_check_and_sleep
        cloud_phantom
    done
}

# DNS-prefetch loop: имитация браузерного DNS preconnect. Тихо, без HTTP.
loop_dns_prefetch() {
    while true; do
        sleep "$(rrange 30 240)"
        vacation_check_and_sleep
        # Берём случайный URL из всех пулов и резолвим только host
        local pool
        case $(( $(urand 0 4) )) in
            0) pool=("${URLS_IOS[@]}") ;;
            1) pool=("${URLS_NEWS_RU[@]}") ;;
            2) pool=("${URLS_IOS_RU_GOV[@]}") ;;
            3) pool=("${URLS_GLOBAL[@]}") ;;
            *) pool=("${URLS_LIB_DOWNLOADS[@]}") ;;
        esac
        if [ "${#pool[@]}" -gt 0 ]; then
            local url="${pool[$(urand 0 $(( ${#pool[@]} - 1 )) )]}"
            dns_prefetch "$url"
        fi
    done
}

# Health-touch loop: каждые 30с обновляет TS в health.json (даже если другие
# loops спят/в vacation), показывает что сервис живой.
loop_health() {
    while true; do
        update_health
        sleep 30
    done
}

# Старт включённых модулей в фоне
PIDS=()
[ "$ENABLE_IOS_BURST"   = "1" ] && { loop_ios   & PIDS+=($!); }
[ "$ENABLE_APNS"        = "1" ] && { loop_apns  & PIDS+=($!); }
[ "${ENABLE_PUSH:-1}"   = "1" ] && { loop_push  & PIDS+=($!); }   # v8.4: APNs/FCM/WNS rotation
[ "${ENABLE_STUN:-1}"   = "1" ] && { loop_stun  & PIDS+=($!); }   # v8.4: WebRTC STUN burst
[ "${ENABLE_WEBSOCKET:-1}" = "1" ] && { loop_ws & PIDS+=($!); }   # v8.4: long-poll TCP keepalive
[ "$ENABLE_EMAIL"       = "1" ] && { loop_email & PIDS+=($!); }
[ "$ENABLE_NEWS"        = "1" ] && { loop_news  & PIDS+=($!); }
[ "$ENABLE_APT_PHANTOM" = "1" ] && command -v apt-get >/dev/null 2>&1 && { loop_apt & PIDS+=($!); }
[ "$ENABLE_LIB_PHANTOM" = "1" ] && { loop_libdl & PIDS+=($!); }
[ "${ENABLE_CLOUD_PHANTOM:-1}" = "1" ] && { loop_cloud & PIDS+=($!); }
[ "${ENABLE_DNS_PREFETCH:-1}"  = "1" ] && { loop_dns_prefetch & PIDS+=($!); }
loop_health & PIDS+=($!)

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
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=300
StartLimitBurst=5
Nice=15
IOSchedulingClass=idle
CPUWeight=20
MemoryHigh=128M
MemoryMax=256M
TasksMax=64
StandardOutput=null
StandardError=null
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictSUIDSGID=yes
LockPersonality=yes
NoNewPrivileges=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
StateDirectory=vps-noise
RuntimeDirectory=vps-noise
RuntimeDirectoryMode=0750
ReadWritePaths=/tmp /var/cache/apt /var/lib/apt /var/lib/vps-noise /run/vps-noise

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
    if [ "$SOFT_RESET" = "1" ]; then
        # Soft-режим (v8.3, L6): откатываем только sysctl/limits/preset.
        # Не трогаем DNS/noise/swap/zram — полезно при отладке тюнинга.
        echo -e "${YELLOW}[*] Soft reset: только sysctl/limits/preset.${NC}"
        rm -f "$SYSCTL_CONF" "$LIMITS_CONF" "$EXP_CONF" "$PRESET_FILE" \
              /etc/systemd/system.conf.d/99-vps-limits.conf \
              /etc/systemd/user.conf.d/99-vps-limits.conf
        # Снимаем boot-unit, если был.
        systemctl disable --now vps-optimizer-apply.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/vps-optimizer-apply.service
        systemctl daemon-reload >/dev/null 2>&1 || true
        sysctl --system >/dev/null 2>&1 || true
        _audit reset "mode=soft"
        echo -e "${GREEN}[+] Soft-сброс выполнен (DNS/noise/swap не тронуты).${NC}"
        sleep 1
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
    systemctl disable --now vps-optimizer-apply.service >/dev/null 2>&1 || true
    # v8.5: cleanup health-watch таймера и rsyslog-фрагмента (created by
    # health_watch_command / audit_syslog_command). Иначе после reset/uninstall
    # таймер продолжает дёргать удалённый скрипт и мусорит в health.log.
    systemctl disable --now vps-optimizer-health.timer >/dev/null 2>&1 || true
    rm -f "$NOISE_GEN_SCRIPT" "$NOISE_GEN_SERVICE" "$RPS_BOOT_SCRIPT" "$RPS_BOOT_SERVICE" \
          /etc/systemd/system/vps-optimizer-apply.service \
          /etc/systemd/system/vps-optimizer-health.timer \
          /etc/systemd/system/vps-optimizer-health.service \
          /etc/rsyslog.d/49-vps-optimizer.conf \
          /etc/unbound/unbound.conf.d/99-vps-optim-dnssec.conf \
          /etc/unbound/unbound.conf.d/99-vps-optim-padding.conf
    # v8.5: если unbound был переведён на dnssec через dns_dnssec_command — reload чтобы
    # подхватить отсутствие фрагмента.
    systemctl reload unbound >/dev/null 2>&1 || true
    systemctl restart rsyslog >/dev/null 2>&1 || true
    rm -rf /tmp/.vps_noise /var/lib/vps-noise
    systemctl daemon-reload >/dev/null 2>&1 || true
    sysctl --system >/dev/null 2>&1 || true
    _audit reset "mode=full"
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
    local tmp tmp_sha new_sha cur_sha
    tmp=$(mktemp /tmp/.vps_optimizer_new.XXXXXX)
    tmp_sha=$(mktemp /tmp/.vps_optimizer_new.XXXXXX.sha)

    if ! curl -fsSL "$SELF_URL" -o "$tmp" || [ ! -s "$tmp" ]; then
        rm -f "$tmp" "$tmp_sha"
        echo -e "${RED}[!] Не удалось скачать $SELF_URL${NC}"
        return 1
    fi

    # 1) bash syntax check
    if ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp" "$tmp_sha"
        echo -e "${RED}[!] Скачанная версия невалидна (syntax error) — обновление отменено.${NC}"
        return 1
    fi

    # 2) SHA256 интегрити-проверка: пробуем скачать sidecar .sha256 (если есть в репе).
    #    При отсутствии — продолжаем с warning (release без подписей).
    if curl -fsSL "${SELF_URL}.sha256" -o "$tmp_sha" 2>/dev/null && [ -s "$tmp_sha" ]; then
        new_sha=$(awk '{print $1}' "$tmp_sha")
        cur_sha=$(file_sha256 "$tmp")
        if [ -n "$new_sha" ] && [ -n "$cur_sha" ] && [ "$new_sha" != "$cur_sha" ]; then
            rm -f "$tmp" "$tmp_sha"
            echo -e "${RED}[!] SHA256 mismatch: ожидалось $new_sha, получено $cur_sha — отмена.${NC}"
            return 1
        fi
        echo -e "${GREEN}[+] SHA256 verified: $cur_sha${NC}"
    else
        echo -e "${GRAY}[i] sha256 sidecar не найден — пропускаем integrity check.${NC}"
    fi

    # 3) Backup текущей версии (если новый сломан — откатим).
    local backup="${SELF_PATH}.bak"
    cp -f "$SELF_PATH" "$backup" 2>/dev/null || true

    chmod +x "$tmp"
    if mv "$tmp" "$SELF_PATH"; then
        # 4) Sanity-check: --help должна работать в новой версии
        if "$SELF_PATH" --help >/dev/null 2>&1 || "$SELF_PATH" help >/dev/null 2>&1; then
            rm -f "$tmp_sha" "$backup"
            echo -e "${GREEN}[+] Скрипт обновлён до последней версии: $SELF_PATH${NC}"
            _audit self_update "ok new_sha=${cur_sha:-skipped}"
            return 0
        else
            cp -f "$backup" "$SELF_PATH" 2>/dev/null || true
            rm -f "$tmp_sha"
            echo -e "${RED}[!] Новая версия не запускается — откат к $backup.${NC}"
            _audit self_update "rolled_back"
            return 1
        fi
    else
        rm -f "$tmp" "$tmp_sha" "$backup"
        echo -e "${RED}[!] Не удалось заменить $SELF_PATH${NC}"
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

    # Создаём manifest с версией формата (для backward-compat при import).
    local manifest="/tmp/.vps_export_manifest.$$.json"
    cat > "$manifest" <<MEOF
{
  "format_version": $EXPORT_FORMAT_VERSION,
  "script_version": "$SCRIPT_VERSION",
  "created_at": "$(date -u +%FT%TZ)",
  "hostname": "$(hostname)",
  "files": ["${files[*]}"]
}
MEOF
    cp "$manifest" /tmp/.vps_export_manifest.json
    files+=(/tmp/.vps_export_manifest.json)

    tar czf "$target" "${files[@]}" 2>/dev/null
    rm -f "$manifest" /tmp/.vps_export_manifest.json
    echo -e "${GREEN}[+] Конфигурация выгружена в $target${NC}"
    echo -e "${GRAY}    Формат: v${EXPORT_FORMAT_VERSION}, файлов: ${#files[@]}${NC}"
    _audit export "target=$target files=${#files[@]}"
}

import_config() {
    local src="${1:?import path required}"
    if [ ! -f "$src" ]; then
        echo -e "${RED}[!] Нет файла: $src${NC}"; return 1
    fi

    # B10: проверяем формат через manifest (если есть).
    local manifest_data fmt_ver scr_ver
    manifest_data=$(tar tzf "$src" 2>/dev/null | grep -m1 'vps_export_manifest.json' || true)
    if [ -n "$manifest_data" ]; then
        local extract_dir
        extract_dir=$(mktemp -d /tmp/.vps_import.XXXXXX)
        tar xzf "$src" -C "$extract_dir" tmp/.vps_export_manifest.json 2>/dev/null || true
        local mf="$extract_dir/tmp/.vps_export_manifest.json"
        if [ -f "$mf" ]; then
            fmt_ver=$(awk -F'[: ,]' '/format_version/{print $4}' "$mf" 2>/dev/null | tr -d '"')
            scr_ver=$(awk -F'"' '/script_version/{print $4}' "$mf" 2>/dev/null)
            echo -e "${GRAY}[i] Архив: format=v${fmt_ver:-?}, script=v${scr_ver:-?}${NC}"
            if [ -n "$fmt_ver" ] && [ "$fmt_ver" -gt "$EXPORT_FORMAT_VERSION" ]; then
                echo -e "${RED}[!] Формат архива (v${fmt_ver}) новее, чем поддерживаемый (v${EXPORT_FORMAT_VERSION}).${NC}"
                echo -e "${YELLOW}    Запусти './vps_optimizer.sh update' и попробуй снова.${NC}"
                rm -rf "$extract_dir"
                return 1
            fi
        fi
        rm -rf "$extract_dir"
    else
        echo -e "${YELLOW}[i] Старый архив без manifest — импортируем как есть.${NC}"
    fi

    if tar xzf "$src" -C / 2>/dev/null; then
        echo -e "${GREEN}[+] Конфигурация импортирована.${NC}"
        rm -f /tmp/.vps_export_manifest.json
        sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart vps-rps vps-noise 2>/dev/null || true
        echo -e "${GREEN}[+] Сервисы перезапущены.${NC}"
        _audit import "src=$src fmt=${fmt_ver:-?} scr=${scr_ver:-?}"
    else
        echo -e "${RED}[!] Распаковка не удалась.${NC}"
        return 1
    fi
}

# ===================================================================
#  CLI parser
# ===================================================================
# ===================================================================
#  v8.2: status --json / logs / audit / harden / uninstall / noise-test
# ===================================================================

# JSON-эскейп для строковых значений.
_json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//	/\\t}"
    printf '"%s"' "$s"
}

# status --json: машиночитаемый вывод для cron / Grafana / Zabbix.
status_json() {
    local virt provider preset bbr qdisc rmem_max wmem_max
    virt=$(detect_virt 2>/dev/null)
    provider=$(detect_provider 2>/dev/null)
    preset="balanced"; [ -f "$PRESET_FILE" ] && preset=$(cat "$PRESET_FILE" 2>/dev/null)
    bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null)
    wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null)

    local conntrack_count conntrack_max ct_used_pct
    conntrack_count=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    conntrack_max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    if [ "$conntrack_max" -gt 0 ] 2>/dev/null; then
        ct_used_pct=$(( conntrack_count * 100 / conntrack_max ))
    else
        ct_used_pct=0
    fi

    local dns_state="local"
    [ -f "$DNS_STATE" ] && dns_state=$(cat "$DNS_STATE" 2>/dev/null)

    local noise_active="inactive" noise_health="{}"
    if systemctl is-active vps-noise >/dev/null 2>&1; then noise_active="active"; fi
    [ -f "$HEALTH_FILE" ] && noise_health=$(cat "$HEALTH_FILE" 2>/dev/null)

    cat <<JEOF
{
  "version": "$SCRIPT_VERSION",
  "virt": $(_json_str "$virt"),
  "provider": $(_json_str "$provider"),
  "preset": $(_json_str "$preset"),
  "bbr": $(_json_str "$bbr"),
  "qdisc": $(_json_str "$qdisc"),
  "rmem_max": ${rmem_max:-0},
  "wmem_max": ${wmem_max:-0},
  "conntrack_count": ${conntrack_count:-0},
  "conntrack_max": ${conntrack_max:-0},
  "conntrack_used_pct": ${ct_used_pct:-0},
  "dns": $(_json_str "$dns_state"),
  "noise_active": $(_json_str "$noise_active"),
  "noise_health": $noise_health
}
JEOF
}

# logs: показать журналы — собственный лог + journalctl + dmesg-сетевые события.
view_logs() {
    local n="${1:-100}"
    echo -e "${CYAN}${BOLD}=== /var/log/vps-optimizer.log (последние $n строк) ===${NC}"
    [ -f "$RUN_LOG" ] && tail -n "$n" "$RUN_LOG" || echo "(пусто)"
    echo ""
    echo -e "${CYAN}${BOLD}=== journalctl: vps-noise + vps-rps (последние $n) ===${NC}"
    journalctl -u vps-noise -u vps-rps --no-pager -n "$n" 2>/dev/null || echo "(нет журналов)"
    echo ""
    echo -e "${CYAN}${BOLD}=== dmesg: TCP / conntrack / OOM ===${NC}"
    # Q7 fix v8.3: 'killed' ловил много ложных, заменили на специфичные OOM-метки.
    dmesg 2>/dev/null | grep -iE 'tcp|conntrack|out of memory|invoked oom-killer|memory cgroup out of memory' | tail -n "$n" || echo "(нет событий)"
    echo ""
    if [ -f "$AUDIT_LOG" ]; then
        echo -e "${CYAN}${BOLD}=== $AUDIT_LOG ===${NC}"
        tail -n 30 "$AUDIT_LOG"
    fi
}

# Парсит sysctl-conf-файл и для каждого key сравнивает ожидаемое значение
# с runtime-значением. Возвращает строки 'KEY|expected|current|status' через
# stdout, где status = OK|DRIFT|UNKNOWN. Формат стабилен — машиночитаемо.
# Q1 fix: используем awk вместо `IFS='='` для корректной обработки знака '='
# в значении (например `kernel.modprobe = /sbin/modprobe -q -k`).
_audit_sysctl_drift_rows() {
    [ -f "$SYSCTL_CONF" ] || return 0
    awk -F'=' '
        /^[[:space:]]*#/ {next}
        NF<2 {next}
        {
            key=$1; gsub(/^[[:space:]]+|[[:space:]]+$/,"",key)
            val=$0; sub(/^[^=]*=/,"",val); gsub(/^[[:space:]]+|[[:space:]]+$/,"",val)
            if (key!="" && val!="") print key "\t" val
        }
    ' "$SYSCTL_CONF" | while IFS=$'\t' read -r key val; do
        local cur
        cur=$(sysctl -n "$key" 2>/dev/null)
        # sysctl возвращает многоколоночное значение через табы — нормализуем к пробелам.
        cur=$(printf '%s' "$cur" | tr -s '[:space:]' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        val=$(printf '%s' "$val" | tr -s '[:space:]' ' ')
        if [ -z "$cur" ]; then
            printf '%s|%s|%s|UNKNOWN\n' "$key" "$val" ""
        elif [ "$cur" = "$val" ]; then
            printf '%s|%s|%s|OK\n' "$key" "$val" "$cur"
        else
            printf '%s|%s|%s|DRIFT\n' "$key" "$val" "$cur"
        fi
    done
}

# audit: полная диагностика VPS — текущие vs ожидаемые sysctl, RPS, conntrack, etc.
audit_command() {
    if [ "$JSON" = "1" ]; then
        audit_json
        return $?
    fi
    print_status_dashboard
    echo ""
    echo -e "${CYAN}${BOLD}=== Глубокий audit ===${NC}"

    # 1. Совпадает ли текущий sysctl с конфигом?
    if [ -f "$SYSCTL_CONF" ]; then
        local mismatched=0
        echo -e "${BOLD}sysctl drift:${NC}"
        local key val cur status
        while IFS='|' read -r key val cur status; do
            case "$status" in
                DRIFT)
                    echo -e "  ${YELLOW}DRIFT${NC} $key: ожидается '$val', текущее '$cur'"
                    mismatched=$(( mismatched + 1 ))
                    ;;
            esac
        done < <(_audit_sysctl_drift_rows)
        if [ "$mismatched" -eq 0 ]; then
            echo -e "  ${GREEN}OK${NC} все ключи совпадают"
        fi
    fi

    # 2. RPS/XPS присутствие
    echo -e "${BOLD}\nRPS/XPS:${NC}"
    local found=0
    for f in /sys/class/net/*/queues/rx-*/rps_cpus; do
        [ -e "$f" ] || continue
        local v
        v=$(cat "$f" 2>/dev/null)
        if [ "$v" != "0" ] && [ "$v" != "00000000" ]; then
            echo -e "  ${GREEN}OK${NC} $f = $v"
            found=$(( found + 1 ))
        fi
    done
    [ "$found" -eq 0 ] && echo -e "  ${YELLOW}WARN${NC} нет настроенных RPS-очередей"

    # 3. Conntrack usage
    local cc cm
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 1)
    if [ "$cm" -gt 0 ]; then
        local pct=$(( cc * 100 / cm ))
        echo -e "${BOLD}\nConntrack:${NC} $cc / $cm (${pct}%)"
        if [ "$pct" -gt 80 ]; then
            echo -e "  ${RED}HIGH${NC} usage > 80% — увеличь nf_conntrack_max"
        fi
    fi

    # 4. Дисковое место
    echo -e "${BOLD}\nDisk:${NC}"
    df -h / 2>/dev/null | tail -1

    # 5. Swap usage
    echo -e "${BOLD}\nSwap:${NC}"
    swapon --show 2>/dev/null | sed 's/^/  /' || echo "  none"

    # 6. dnscrypt-proxy listener
    if systemctl is-active dnscrypt-proxy >/dev/null 2>&1; then
        echo -e "${BOLD}\ndnscrypt-proxy:${NC} ${GREEN}active${NC}"
        ss -lntu 2>/dev/null | grep -E ':53|:5300' | head -3 | sed 's/^/  /'
    fi

    # 7. Noise health
    if [ -f "$HEALTH_FILE" ]; then
        echo -e "${BOLD}\nNoise health:${NC}"
        cat "$HEALTH_FILE"
    fi

    # 8. Audit-log size
    if [ -f "$AUDIT_LOG" ]; then
        local sz lines
        sz=$(stat -c%s "$AUDIT_LOG" 2>/dev/null || echo 0)
        lines=$(wc -l < "$AUDIT_LOG" 2>/dev/null || echo 0)
        echo -e "${BOLD}\nAudit log:${NC} $sz байт, $lines записей"
    fi

    # 9. PTR sanity check (v8.3, N7) — мягкое предупреждение, не блокирует.
    echo ""
    ptr_sanity_check
}

# PTR sanity check: сравниваем reverse-DNS внешнего IP с прямым A-запросом.
# Несовпадение — частый признак странной CDN-конфигурации или хостинга,
# где PTR не настроен. Только warn, никогда не блокирует.
ptr_sanity_check() {
    if ! command -v dig >/dev/null 2>&1 && ! command -v getent >/dev/null 2>&1; then
        return 0
    fi
    local ext_ip ptr fwd
    ext_ip=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
        || curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null \
        || echo "")
    if [ -z "$ext_ip" ]; then
        return 0
    fi
    echo -e "${BOLD}PTR sanity:${NC} external IP=$ext_ip"
    if command -v dig >/dev/null 2>&1; then
        ptr=$(dig +short -x "$ext_ip" 2>/dev/null | sed 's/\.$//' | head -1)
    else
        ptr=$(getent hosts "$ext_ip" 2>/dev/null | awk '{print $2}' | head -1)
    fi
    if [ -z "$ptr" ]; then
        echo -e "  ${YELLOW}WARN${NC} нет PTR-записи для $ext_ip (некоторые SMTP-серверы откажут)"
        return 0
    fi
    echo "  PTR: $ptr"
    if command -v dig >/dev/null 2>&1; then
        fwd=$(dig +short A "$ptr" 2>/dev/null | head -1)
    else
        fwd=$(getent hosts "$ptr" 2>/dev/null | awk '{print $1}' | head -1)
    fi
    if [ -z "$fwd" ]; then
        echo -e "  ${YELLOW}WARN${NC} forward A для $ptr не разрешается"
    elif [ "$fwd" = "$ext_ip" ]; then
        echo -e "  ${GREEN}OK${NC} PTR <-> A совпадают"
    else
        echo -e "  ${YELLOW}WARN${NC} PTR ($ptr -> $fwd) не совпадает с внешним IP ($ext_ip)"
    fi
}

# audit --json: машиночитаемая версия audit_command (v8.3, M14).
audit_json() {
    local rows drift_count ok_count unknown_count
    rows=$(_audit_sysctl_drift_rows)
    drift_count=$(printf '%s\n' "$rows" | grep -c '|DRIFT$' || true)
    ok_count=$(printf '%s\n' "$rows" | grep -c '|OK$' || true)
    unknown_count=$(printf '%s\n' "$rows" | grep -c '|UNKNOWN$' || true)
    local cc cm pct=0
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    [ "$cm" -gt 0 ] && pct=$(( cc * 100 / cm ))

    local rps_active=0 f
    for f in /sys/class/net/*/queues/rx-*/rps_cpus; do
        [ -e "$f" ] || continue
        local v
        v=$(cat "$f" 2>/dev/null)
        if [ "$v" != "0" ] && [ "$v" != "00000000" ]; then
            rps_active=$(( rps_active + 1 ))
        fi
    done

    local audit_size=0 audit_lines=0
    if [ -f "$AUDIT_LOG" ]; then
        audit_size=$(stat -c%s "$AUDIT_LOG" 2>/dev/null || echo 0)
        audit_lines=$(wc -l < "$AUDIT_LOG" 2>/dev/null || echo 0)
    fi

    # JSON-stream массив drifts — каждая строка из rows как объект.
    local drifts_json="[]"
    if command -v jq >/dev/null 2>&1; then
        drifts_json=$(printf '%s\n' "$rows" | awk -F'|' 'NF==4 {
            printf "{\"key\":\"%s\",\"expected\":\"%s\",\"current\":\"%s\",\"status\":\"%s\"}\n", $1,$2,$3,$4
        }' | jq -s . 2>/dev/null || echo "[]")
    fi

    cat <<JSON
{
  "version": "$SCRIPT_VERSION",
  "ts": "$(date -u +%FT%TZ)",
  "sysctl": {
    "ok": $ok_count,
    "drift": $drift_count,
    "unknown": $unknown_count,
    "rows": $drifts_json
  },
  "rps": {"active_queues": $rps_active},
  "conntrack": {"count": $cc, "max": $cm, "pct": $pct},
  "audit_log": {"size_bytes": $audit_size, "lines": $audit_lines}
}
JSON
}

# doctor: actionable-диагностика (v8.3, M1).
# Не ругается без причины, говорит что именно делать. Сейчас проверяет 8
# самых частых проблем, которые мы реально умеем чинить.
doctor_command() {
    echo -e "${CYAN}${BOLD}=== vps-optimizer doctor v${SCRIPT_VERSION} ===${NC}"
    echo ""
    local issues=0

    # 1. Conntrack usage
    local cc cm pct
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    if [ "$cm" -gt 0 ]; then
        pct=$(( cc * 100 / cm ))
        if [ "$pct" -ge 80 ]; then
            echo -e "${RED}[!] conntrack ${pct}%${NC} ($cc/$cm)"
            echo "    Fix: подними net.netfilter.nf_conntrack_max до $((cm * 2))"
            echo "         echo 'net.netfilter.nf_conntrack_max=$((cm * 2))' >> $SYSCTL_CONF && sysctl -p $SYSCTL_CONF"
            issues=$(( issues + 1 ))
        else
            echo -e "${GREEN}[ok]${NC} conntrack ${pct}% ($cc/$cm)"
        fi
    fi

    # 2. TCP retransmits — рассчитываем delta за 1 сек.
    # /proc/net/snmp имеет 2 'Tcp:' строки: первая — заголовок с именами колонок,
    # вторая — значения. Берём индексы из header'а, значения из data-строки.
    if [ -r /proc/net/snmp ]; then
        local rt1 rt2 sg1 sg2 retrans_pct=0
        # shellcheck disable=SC2016
        local awk_pick='/^Tcp:/ && !hdr {hdr=$0; next} /^Tcp:/ {n=split(hdr,h); m=split($0,d); for(i=1;i<=n;i++) if(h[i]==key) {print d[i]+0; exit}}'
        rt1=$(awk -v key=RetransSegs "$awk_pick" /proc/net/snmp 2>/dev/null)
        sg1=$(awk -v key=OutSegs    "$awk_pick" /proc/net/snmp 2>/dev/null)
        sleep 1
        rt2=$(awk -v key=RetransSegs "$awk_pick" /proc/net/snmp 2>/dev/null)
        sg2=$(awk -v key=OutSegs    "$awk_pick" /proc/net/snmp 2>/dev/null)
        local d_rt d_sg
        d_rt=$(( ${rt2:-0} - ${rt1:-0} ))
        d_sg=$(( ${sg2:-0} - ${sg1:-0} ))
        if [ "$d_sg" -gt 0 ]; then
            retrans_pct=$(( d_rt * 100 / d_sg ))
        fi
        if [ "$retrans_pct" -ge 5 ]; then
            echo -e "${YELLOW}[!] TCP retransmits ${retrans_pct}%/s${NC} ($d_rt из $d_sg сегментов)"
            echo "    Causes: плохая сеть, MTU mismatch, сильно нагружен link."
            echo "    Fix: проверь MTU (sudo $0 wg setup автодетектит для wg-iface)"
            echo "         посмотри dmesg | grep -E 'tcp|conntrack'"
            issues=$(( issues + 1 ))
        else
            echo -e "${GREEN}[ok]${NC} TCP retransmits ${retrans_pct}%/s"
        fi
    fi

    # 3. softnet_stat — drops/squeezed (значения в hex; portable hex→dec через bash).
    if [ -r /proc/net/softnet_stat ]; then
        local drops=0 squeezed=0 col1 col2 col3
        while read -r col1 col2 col3 _; do
            : "$col1"  # processed unused
            # bash 16#XX = hex → dec; защищаемся от пустых/мусорных строк.
            [[ "$col2" =~ ^[0-9a-fA-F]+$ ]] && drops=$(( drops + 16#$col2 ))
            [[ "$col3" =~ ^[0-9a-fA-F]+$ ]] && squeezed=$(( squeezed + 16#$col3 ))
        done < /proc/net/softnet_stat
        if [ "$drops" -gt 1000 ] || [ "$squeezed" -gt 1000 ]; then
            echo -e "${YELLOW}[!] softnet drops=$drops, squeezed=$squeezed${NC}"
            echo "    Fix: подними net.core.netdev_max_backlog (текущий: $(sysctl -n net.core.netdev_max_backlog 2>/dev/null))"
            echo "         или включи RPS (apply сделает)"
            issues=$(( issues + 1 ))
        else
            echo -e "${GREEN}[ok]${NC} softnet drops=$drops squeezed=$squeezed"
        fi
    fi

    # 4. Disk space на /var
    local var_pct
    var_pct=$(df --output=pcent /var 2>/dev/null | tail -1 | tr -dc '0-9')
    if [ -n "$var_pct" ] && [ "$var_pct" -ge 90 ]; then
        echo -e "${RED}[!] /var заполнен на ${var_pct}%${NC}"
        echo "    Fix: journalctl --vacuum-time=7d; rotate logs; check $SNAPSHOT_DIR"
        issues=$(( issues + 1 ))
    else
        echo -e "${GREEN}[ok]${NC} /var свободно: $((100 - ${var_pct:-0}))%"
    fi

    # 5. DNS работает?
    if ! getent hosts cloudflare.com >/dev/null 2>&1; then
        echo -e "${RED}[!] DNS не разрешается${NC}"
        echo "    Fix: sudo $0 dns local   # вернуть провайдерский DNS"
        echo "         или: sudo $0 dns plain cloudflare"
        issues=$(( issues + 1 ))
    else
        echo -e "${GREEN}[ok]${NC} DNS отвечает"
    fi

    # 6. Auto-rollback snapshot за последний час
    local recent_snap
    recent_snap=$(find "$SNAPSHOT_DIR" -maxdepth 1 -name 'pre-apply-*.tar.gz' -mmin -60 2>/dev/null | head -1)
    if [ -n "$recent_snap" ]; then
        echo -e "${GREEN}[ok]${NC} Свежий snapshot: $(basename "$recent_snap")"
    fi

    # 7. Hypervisor
    local virt
    virt=$(detect_virt)
    case "$virt" in
        openvz|lxc)
            echo -e "${YELLOW}[i]${NC} hypervisor=$virt — часть тюнингов запрещена хостом, это нормально"
            ;;
        kvm|xen|hyperv|microsoft|none)
            echo -e "${GREEN}[ok]${NC} hypervisor=$virt — полный тюнинг доступен"
            ;;
    esac

    # 8. VPN-iface наличие
    if has_vpn_iface; then
        echo -e "${GREEN}[ok]${NC} VPN-iface обнаружен — рекомендуется apply --vpn"
    fi

    # 9. (v8.4) ss -tin top connections by retransmits — реальная картина а не sysctl drift
    if command -v ss >/dev/null 2>&1; then
        local top_retr
        top_retr=$(ss -tin state established 2>/dev/null \
            | awk '/retrans/ {
                for (i=1; i<=NF; i++) {
                    if ($i ~ /^retrans:/) {
                        n=split($i, a, "/")
                        if (n>=2 && a[2]+0 > 0) print a[2]"\t"$0
                    }
                }
              }' | sort -rn -k1 | head -3)
        if [ -n "$top_retr" ]; then
            echo -e "${YELLOW}[i]${NC} top-3 connections by retransmits (live ss -tin):"
            echo "$top_retr" | awk '{ printf "    %s retrans, line=%s\n", $1, substr($0, length($1)+2, 90) }'
        fi
    fi

    # 10. (v8.4) PCIe link generation warning — VPS-провайдеры иногда выделяют gen3 вместо gen4
    if command -v lspci >/dev/null 2>&1; then
        local pcie_warn
        pcie_warn=$(lspci -vv 2>/dev/null | awk '
            /Ethernet/ { eth_seen=1; eth_block=$0; next }
            eth_seen && /LnkCap:.*Speed/ {
                if ($0 ~ /Speed 8GT\/s/) print "Ethernet NIC: PCIe gen3 (8 GT/s) — на gen4-капабельной hw мог быть gen4 (16 GT/s)"
                eth_seen=0
            }')
        [ -n "$pcie_warn" ] && echo -e "${YELLOW}[i]${NC} $pcie_warn"
    fi

    # 11. (v8.4) kTLS статус
    if [ -d /sys/module/tls ]; then
        echo -e "${GREEN}[ok]${NC} kTLS модуль загружен (sendfile-on-TLS доступен для nginx-ktls/h2o)"
    else
        echo -e "${GRAY}[i]${NC} kTLS модуль не загружен — выполни: modprobe tls"
    fi

    # 12. (v8.5) systemd-resolved coexistence — частая причина «DNS не отвечает»
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if systemctl is-active --quiet dnsmasq 2>/dev/null; then
            echo -e "${YELLOW}[!] systemd-resolved + dnsmasq оба активны${NC} — конфликт за :53"
            echo "    Fix: либо systemctl disable --now systemd-resolved,"
            echo "         либо настрой systemd-resolved слушать только linklocal:"
            echo "         echo 'DNSStubListener=no' >> /etc/systemd/resolved.conf"
            issues=$(( issues + 1 ))
        else
            echo -e "${GREEN}[ok]${NC} systemd-resolved активен (dnsmasq не используется)"
        fi
    fi

    # 13. (v8.5) ip_local_port_range — широкий диапазон ephemeral портов
    # снижает риск EADDRINUSE под high-throughput proxy. Меньше 20000 портов —
    # бутылочное горлышко. Реальный Safari использует 49152-65535, но дефолт
    # ядра обычно 32768-60999, что нормально (Safari fingerprint — minor leak).
    local lpr
    lpr=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null)
    if [ -n "$lpr" ]; then
        local lo hi span
        read -r lo hi <<<"$lpr"
        span=$(( hi - lo ))
        if [ "$span" -lt 20000 ]; then
            echo -e "${YELLOW}[i]${NC} ip_local_port_range=$lo-$hi (span=$span) — узкий, риск EADDRINUSE"
        else
            echo -e "${GREEN}[ok]${NC} ip_local_port_range=$lo-$hi (span=$span)"
        fi
    fi

    # 14. (v8.5) bpftool prog show — какие eBPF-программы загружены
    if command -v bpftool >/dev/null 2>&1; then
        local bpf_progs
        bpf_progs=$(bpftool prog show 2>/dev/null | grep -c '^[0-9]' || echo 0)
        if [ "$bpf_progs" -gt 0 ]; then
            echo -e "${GREEN}[ok]${NC} eBPF: $bpf_progs программ загружено (bpftool prog show — детали)"
        fi
    fi

    # 15. (v8.5) WireGuard kernel vs userspace
    if command -v wg >/dev/null 2>&1; then
        local wg_links
        wg_links=$(wg show interfaces 2>/dev/null | wc -w)
        if [ "$wg_links" -gt 0 ]; then
            if lsmod 2>/dev/null | grep -q '^wireguard '; then
                echo -e "${GREEN}[ok]${NC} WireGuard: kernel-mode (быстро)"
            elif pgrep -x wireguard-go >/dev/null 2>&1; then
                echo -e "${YELLOW}[i]${NC} WireGuard: userspace (wireguard-go) — kernel-mode дал бы +30-50% throughput"
            fi
        fi
    fi

    # 16. (v8.7) UDP drop counter / SO_RXQ_OVFL — для QUIC/WireGuard критично.
    # /proc/net/snmp колонки InErrors / RcvbufErrors. Если RcvbufErrors быстро
    # растёт — UDP receive buffer переполняется (надо повышать net.core.rmem_max
    # / optmem_max). Проверяем накопленное значение, warning при > 1000.
    if [ -r /proc/net/snmp ]; then
        local snmp_udp_line snmp_udp_hdr rcvbuf_pos inerr_pos rcvbuf_val inerr_val
        snmp_udp_hdr=$(grep '^Udp:' /proc/net/snmp 2>/dev/null | sed -n '1p')
        snmp_udp_line=$(grep '^Udp:' /proc/net/snmp 2>/dev/null | sed -n '2p')
        if [ -n "$snmp_udp_hdr" ] && [ -n "$snmp_udp_line" ]; then
            rcvbuf_pos=$(echo "$snmp_udp_hdr" | tr ' ' '\n' | grep -n '^RcvbufErrors$' | cut -d: -f1)
            inerr_pos=$(echo "$snmp_udp_hdr" | tr ' ' '\n' | grep -n '^InErrors$' | cut -d: -f1)
            if [ -n "$rcvbuf_pos" ]; then
                rcvbuf_val=$(echo "$snmp_udp_line" | awk -v p="$rcvbuf_pos" '{print $p}')
                inerr_val=$(echo "$snmp_udp_line" | awk -v p="$inerr_pos" '{print $p}')
                if [ -n "$rcvbuf_val" ] && [ "$rcvbuf_val" -gt 1000 ] 2>/dev/null; then
                    echo -e "${YELLOW}[!]${NC} UDP RcvbufErrors=$rcvbuf_val (>1000) — буфер переполняется, повышай net.core.rmem_max/optmem_max"
                    issues=$((issues+1))
                elif [ -n "$rcvbuf_val" ]; then
                    echo -e "${GREEN}[ok]${NC} UDP RcvbufErrors=$rcvbuf_val (норма)"
                fi
                if [ -n "$inerr_val" ] && [ "$inerr_val" -gt 10000 ] 2>/dev/null; then
                    echo -e "${YELLOW}[!]${NC} UDP InErrors=$inerr_val (>10000) — overload UDP listener'ов"
                    issues=$((issues+1))
                fi
            fi
        fi
    fi

    echo ""
    if [ "$issues" -eq 0 ]; then
        echo -e "${GREEN}${BOLD}=== всё ок, проблем не найдено ===${NC}"
    else
        echo -e "${YELLOW}${BOLD}=== найдено $issues проблем(ы) — см. выше ===${NC}"
    fi
}

# why <key>: объясняем почему конкретный sysctl такой (v8.3, M2).
# База знаний — короткие пояснения для ~30 наших ключевых knob'ов.
why_command() {
    local key="$1" cur expected
    cur=$(sysctl -n "$key" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
    if [ -z "$cur" ]; then
        echo -e "${RED}[!] $key не существует или не читается${NC}"
        return 1
    fi
    if [ -f "$SYSCTL_CONF" ]; then
        expected=$(awk -F'=' -v k="$key" '
            $1 ~ k {sub(/^[^=]*=/,""); gsub(/^ +| +$/,""); print; exit}
        ' "$SYSCTL_CONF")
    fi
    echo -e "${BOLD}$key${NC}"
    echo "  current:  $cur"
    [ -n "$expected" ] && echo "  applied:  $expected"
    echo ""
    case "$key" in
        net.ipv4.tcp_rmem|net.ipv4.tcp_wmem)
            echo "  Min/default/max буфер TCP per-socket. На VPS с RAM>=4GB и 10G+ линке"
            echo "  max=512MB позволяет вместить bandwidth*delay product без drop'ов."
            ;;
        net.core.rmem_max|net.core.wmem_max)
            echo "  Глобальный максимум sock-buffer. Должен быть >= max(tcp_rmem)."
            ;;
        net.ipv4.tcp_congestion_control)
            echo "  Алгоритм управления окном. BBR — лучший выбор для прокси/VPN"
            echo "  (loss-tolerant). cubic — для классики. bbr3/bbr2 — экспериментально."
            ;;
        net.core.default_qdisc)
            echo "  Дефолтный qdisc для всех iface. fq — pacing-friendly для BBR."
            echo "  cake — pareto-оптимально для bufferbloat."
            ;;
        net.ipv4.conf.all.rp_filter)
            echo "  Reverse Path Filtering. =0 off, =1 strict (дропает asymmetric routing —"
            echo "  ломает VPN/MPTCP), =2 loose (защита от source-spoofing, дружит с VPN)."
            echo "  v8.3 ставит =2 по умолчанию."
            ;;
        net.ipv4.tcp_fastopen)
            echo "  TFO позволяет данные в SYN-пакете. =3 = client+server."
            echo "  v8.3 также сбрасывает blackhole_timeout — иначе TFO выключается на час."
            ;;
        net.ipv4.tcp_fastopen_blackhole_timeout_sec)
            echo "  Если ядро решило что TFO в чёрной дыре, лочит на N секунд (default 3600)."
            echo "  =0 (v8.3) — никогда не лочить, всегда пытаемся TFO."
            ;;
        net.ipv4.udp_rmem_min|net.ipv4.udp_wmem_min)
            echo "  Минимальный UDP-buffer per-socket. Критично для QUIC/Hysteria/WireGuard"
            echo "  где socket-buffers могут быть >1MB."
            ;;
        net.ipv4.udp_mem)
            echo "  Глобальный UDP memory pressure (в страницах, не байтах!). low/pressure/max."
            ;;
        net.netfilter.nf_conntrack_max)
            echo "  Максимум одновременных conntrack-записей. Прокси/NAT упирается"
            echo "  быстро. preset proxy ставит до 4M. balance — 1M."
            ;;
        net.core.netdev_max_backlog)
            echo "  Очередь пакетов между NIC и кернел-stack. v8.3 масштабирует под скорость:"
            echo "  >=25G → 300000, >=10G → 100000, иначе 30000."
            ;;
        net.core.dev_weight)
            echo "  Сколько пакетов napi обрабатывает за один poll. Выше = меньше"
            echo "  context-switch'ей, но потенциально выше latency. v8.3: 64-128 по линку."
            ;;
        net.ipv4.ip_forward)
            echo "  Маршрутизация через хост. =1 нужно для VPN-сервера / контейнерного хоста."
            echo "  v8.3 включает только если детектим tun*/wg*/ppp* или передан --vpn."
            ;;
        net.ipv4.tcp_keepalive_time)
            echo "  Сколько секунд idle прежде чем послать keepalive-probe. По умолчанию"
            echo "  7200 (2 часа) — слишком много для прокси за NAT'ом, ставим 300."
            ;;
        vm.swappiness)
            echo "  Насколько охотно ядро своппит. 60 = default, 10 = мало, 1 = почти никогда."
            echo "  С zram swappiness=100-200 имеет смысл (compression быстрее disk-IO)."
            ;;
        net.ipv4.tcp_mtu_probing)
            echo "  Probe для PMTU. =0 off, =1 on if blackhole, =2 always."
            echo "  Лечит чёрные дыры в туннелях (WireGuard/Reality/XHTTP)."
            ;;
        *)
            echo "  Описание для этого ключа не зашито. См. man 7 tcp / man 7 udp / kernel docs:"
            echo "  https://www.kernel.org/doc/Documentation/sysctl/"
            ;;
    esac
}

# wg setup: WireGuard helper (v8.3, J1) — ставит wireguard-tools, генерит
# минимальный config с автодетектом MTU (через ICMP needs-frag), conntrack-rules.
# Полностью opt-in. Если WG уже настроен — не трогает.
wg_setup() {
    echo -e "${CYAN}${BOLD}=== WireGuard helper (opt-in) ===${NC}"

    # 1. Установка wireguard-tools если ещё нет.
    if ! command -v wg >/dev/null 2>&1; then
        echo "[*] Ставим wireguard-tools..."
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wireguard-tools >/dev/null 2>&1 || {
                echo -e "${RED}[!] Не удалось установить wireguard-tools${NC}"; return 1
            }
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y wireguard-tools >/dev/null 2>&1 || return 1
        else
            echo -e "${RED}[!] Менеджер пакетов не определён${NC}"; return 1
        fi
    fi
    echo -e "${GREEN}[+] wireguard-tools: $(wg --version | head -1)${NC}"

    # 2. Автодетект оптимального MTU.
    # ICMP может быть отфильтрован — в этом случае берём безопасный 1280.
    local default_iface mtu_phys mtu_wg
    default_iface=$(ip -4 route show default 2>/dev/null | awk '/^default/{for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
    mtu_phys=$(cat "/sys/class/net/${default_iface:-eth0}/mtu" 2>/dev/null || echo 1500)
    # WG-overhead: IP(20) + UDP(8) + WG-header(32) = 60 для IPv4, 80 для IPv6.
    mtu_wg=$(( mtu_phys - 80 ))
    [ "$mtu_wg" -lt 1280 ] && mtu_wg=1280
    echo "[*] Phys MTU: $mtu_phys (iface: ${default_iface:-eth0}) → WG MTU: $mtu_wg"

    # 3. Генерим ключи если не существуют.
    local wg_dir=/etc/wireguard
    mkdir -p "$wg_dir"
    chmod 700 "$wg_dir"
    if [ ! -f "$wg_dir/server.key" ]; then
        echo "[*] Генерим ключевую пару..."
        (umask 077; wg genkey | tee "$wg_dir/server.key" | wg pubkey > "$wg_dir/server.pub")
        echo -e "${GREEN}[+] Ключи: $wg_dir/server.key, $wg_dir/server.pub${NC}"
    else
        echo "[*] Ключи уже существуют: $wg_dir/server.key (не трогаем)"
    fi

    # 4. Минимальный server config (только если ещё нет).
    if [ ! -f "$wg_dir/wg0.conf" ]; then
        local priv_key pub_key
        priv_key=$(cat "$wg_dir/server.key")
        pub_key=$(cat "$wg_dir/server.pub")
        cat > "$wg_dir/wg0.conf" <<WG_EOF
# Generated by vps_optimizer v${SCRIPT_VERSION} (wg setup)
# https://github.com/lpxqwkjd65rjfn-dot/noble-net-warp
[Interface]
PrivateKey = $priv_key
ListenPort = 51820
Address = 10.99.0.1/24
MTU = $mtu_wg
# v8.6: UDP_GRO/SO_REUSEPORT — современное wg-tools/wireguard-linux уже умеет
# UDP-GRO listen-side при условии что net.core.devconf'ы выставлены, что мы
# делаем в apply. Дополнительно ничего не нужно — это для документирования.
# PreUp/PostDown ниже — типовая NAT-настройка для VPN-роутера.
# Закомментировано по умолчанию: включай руками если хочешь exit-node.
# PostUp   = iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o ${default_iface:-eth0} -j MASQUERADE
# PostDown = iptables -t nat -D POSTROUTING -s 10.99.0.0/24 -o ${default_iface:-eth0} -j MASQUERADE

# Public key (раздавай клиентам): $pub_key

# Чтобы добавить клиента — допиши блок:
# [Peer]
# PublicKey = <client-pubkey>
# AllowedIPs = 10.99.0.2/32
# PersistentKeepalive = 25
WG_EOF
        chmod 600 "$wg_dir/wg0.conf"
        echo -e "${GREEN}[+] Server config: $wg_dir/wg0.conf${NC}"
        echo "    Public key: $pub_key"
    else
        echo "[*] $wg_dir/wg0.conf уже существует — не трогаем."
    fi

    # 5. ip_forward — без него VPN не маршрутизирует.
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

    echo ""
    echo -e "${CYAN}Дальнейшие шаги:${NC}"
    echo "  1. systemctl enable --now wg-quick@wg0"
    echo "  2. Открой UDP/51820 в фаерволе:  ufw allow 51820/udp"
    echo "  3. Добавь Peer-блоки в $wg_dir/wg0.conf для клиентов"
    echo "  4. После apply --vpn — sysctl будут VPN-friendly (rp_filter=2 и т.д.)"
    _audit wg_setup "mtu=$mtu_wg iface=${default_iface:-eth0}"
}

# install_apply_boot_unit: ставит one-shot systemd unit, который запускает
# apply на каждом boot (v8.3, M13). Полезно для OpenVZ, где /etc/sysctl.d/
# иногда вытирается провайдером.
install_apply_boot_unit() {
    if [ "$DRY_RUN" = "1" ]; then
        echo -e "${YELLOW}[dry-run] install_apply_boot_unit: показал бы как бы выглядел unit.${NC}"
        return 0
    fi
    local self
    self=$(readlink -f "${BASH_SOURCE[0]:-$0}")
    cat > /etc/systemd/system/vps-optimizer-apply.service <<UNIT_EOF
[Unit]
Description=VPS Optimizer apply on boot (vps-optimizer v${SCRIPT_VERSION})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$self apply --quiet --no-rollback
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT_EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable vps-optimizer-apply.service >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] vps-optimizer-apply.service установлен.${NC}"
    echo "    apply будет автоматически запускаться при каждом boot'е."
    echo "    Снять: systemctl disable --now vps-optimizer-apply.service"
    _audit apply_boot "installed unit=vps-optimizer-apply.service script=$self"
}

# noise test --once: запустить один цикл без записи в systemd
noise_test() {
    if [ ! -f "$NOISE_GEN_SCRIPT" ]; then
        echo -e "${RED}[!] $NOISE_GEN_SCRIPT не существует — сначала запусти 'noise on'${NC}"
        return 1
    fi
    echo -e "${CYAN}[*] Однократный прогон шумогенератора (test mode):${NC}"
    # Запускаем bash-скрипт с переменной NOISE_TEST_ONCE — он должен прочитать
    # и сделать один цикл. Текущий скрипт это не поддерживает на 100%, поэтому
    # делаем простую версию: показать какие профили включены и запустить ios_burst.
    (
        # shellcheck source=/dev/null
        [ -f "$NOISE_CONF" ] && set -a && . "$NOISE_CONF" && set +a
        echo "  PROFILE=${PROFILE:-?}"
        echo "  ENABLE_IOS_BURST=${ENABLE_IOS_BURST:-?}"
        echo "  ENABLE_NEWS=${ENABLE_NEWS:-?}"
        echo "  ENABLE_EMAIL=${ENABLE_EMAIL:-?}"
        echo "  ENABLE_LIB_PHANTOM=${ENABLE_LIB_PHANTOM:-?}"
        echo "  ENABLE_CLOUD_PHANTOM=${ENABLE_CLOUD_PHANTOM:-?}"
        echo "  PLACE_PROFILE=${PLACE_PROFILE:-auto}"
        echo "  Текущий hour_factor: $(date +%H)h"
    )
    echo ""
    echo -e "${GRAY}[i] Реальный прогон производится сервисом vps-noise.service.${NC}"
    echo -e "${GRAY}    Чтобы увидеть live-трафик: journalctl -u vps-noise -f${NC}"
}

# uninstall: удалить ВСЁ — конфиги, скрипты, сервисы. Ставит точку.
uninstall_command() {
    echo -e "${RED}${BOLD}=== UNINSTALL ===${NC}"
    echo -e "${YELLOW}Это удалит:${NC}"
    echo "  - Все sysctl/limits конфиги"
    echo "  - vps-noise.service, vps-rps.service"
    echo "  - $NOISE_GEN_SCRIPT, $RPS_BOOT_SCRIPT"
    echo "  - $AUDIT_LOG, $RUN_LOG, $DEBUG_LOG"
    echo "  - $SNAPSHOT_DIR/, /var/lib/vps-noise/"
    echo "  - сам скрипт $SELF_PATH"
    echo ""
    if [ "$FORCE" != "1" ]; then
        read -r -p "Подтверди (yes для удаления): " confirm
        [ "$confirm" = "yes" ] || { echo "Отменено."; return 0; }
    fi

    # 1) Сначала reset (откатывает все настройки)
    reset_all

    # 2) Удаляем audit/run/debug-логи и снапшоты
    rm -f "$AUDIT_LOG" "$RUN_LOG" "$DEBUG_LOG"
    rm -rf "$SNAPSHOT_DIR" /var/lib/vps-noise /run/vps-noise

    # 3) Удаляем сам скрипт
    if [ -f "$SELF_PATH" ]; then
        rm -f "$SELF_PATH" "${SELF_PATH}.bak"
        echo -e "${GREEN}[+] $SELF_PATH удалён.${NC}"
    fi

    _audit uninstall "complete"
    echo -e "${GREEN}${BOLD}[+] Uninstall завершён.${NC}"
}

# harden: включить opt-in security (UFW + SSH-baseline + unattended-upgrades).
# НЕ затрагивает базовый apply — это отдельная команда.
harden_command() {
    local target="${1:-all}"
    case "$target" in
        ufw|firewall)        harden_ufw ;;
        ssh)                 harden_ssh ;;
        upgrades|unattended) harden_unattended_upgrades ;;
        all)                 harden_ufw; harden_ssh; harden_unattended_upgrades ;;
        *)
            echo -e "${YELLOW}harden: укажи цель${NC}"
            echo "  harden ssh        — SSH baseline (MaxAuthTries, LoginGraceTime, banner)"
            echo "  harden ufw        — UFW preset (allow ssh + deny incoming default)"
            echo "  harden upgrades   — unattended-upgrades security-only"
            echo "  harden all        — всё сразу"
            return 1
            ;;
    esac
    _audit harden "target=$target"
}

harden_ufw() {
    if ! command -v ufw >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -yq ufw >/dev/null
        else
            echo -e "${RED}[!] ufw не установлен и apt недоступен.${NC}"; return 1
        fi
    fi
    echo -e "${CYAN}[*] Настраиваем UFW${NC}"
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    # SSH (порт из sshd_config)
    local ssh_port
    ssh_port=$(awk '/^Port[[:space:]]/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
    [ -z "$ssh_port" ] && ssh_port=22
    ufw allow "$ssh_port"/tcp comment 'SSH' >/dev/null 2>&1
    # ICMP echo-request/reply остаются в before.rules по умолчанию — не трогаем.
    ufw --force enable >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] UFW активирован, разрешён SSH на порту $ssh_port.${NC}"
}

harden_ssh() {
    local sshd_cfg=/etc/ssh/sshd_config
    [ -f "$sshd_cfg" ] || { echo -e "${YELLOW}[!] $sshd_cfg отсутствует — пропуск.${NC}"; return 0; }
    local drop=/etc/ssh/sshd_config.d/99-vps-optimizer-harden.conf
    mkdir -p "$(dirname "$drop")" 2>/dev/null
    cat > "$drop" <<SEOF
# v8.2 SSH baseline (vps_optimizer harden ssh)
MaxAuthTries 3
LoginGraceTime 20
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
Banner /etc/issue.net
SEOF
    if [ -s /etc/issue.net ] && ! grep -q 'Authorized access only' /etc/issue.net 2>/dev/null; then
        cp -a /etc/issue.net "/etc/issue.net.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    cat > /etc/issue.net <<'BEOF'
**********************************************************************
*  Authorized access only. All activity is logged and monitored.     *
*  Disconnect IMMEDIATELY if you are not an authorized user.         *
**********************************************************************
BEOF
    if sshd -t 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        echo -e "${GREEN}[+] SSH baseline применён ($drop)${NC}"
    else
        rm -f "$drop"
        echo -e "${RED}[!] sshd -t не прошёл — конфиг откачен.${NC}"
        return 1
    fi
}

harden_unattended_upgrades() {
    if ! command -v apt-get >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] apt не найден — пропуск unattended-upgrades.${NC}"; return 0
    fi
    apt-get install -yq unattended-upgrades apt-listchanges >/dev/null 2>&1 || true
    cat > /etc/apt/apt.conf.d/52unattended-upgrades-vps <<'UEOF'
// v8.2: security-only unattended-upgrades (vps_optimizer harden upgrades)
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
UEOF
    cat > /etc/apt/apt.conf.d/20auto-upgrades-vps <<'AEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AEOF
    systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] unattended-upgrades активирован (только security).${NC}"
}

# ===================================================================
#  v8.2: Prometheus exporter / autotune-stub / compare-baseline
# ===================================================================

# Prometheus-формат текстовых метрик. Печатает на stdout, использовать с
# socat/nc/python3 -m http.server для экспонирования на порт 9777.
prom_metrics() {
    local virt provider preset bbr qdisc rmem_max wmem_max
    virt=$(detect_virt 2>/dev/null)
    provider=$(detect_provider 2>/dev/null)
    preset="balanced"; [ -f "$PRESET_FILE" ] && preset=$(cat "$PRESET_FILE" 2>/dev/null)
    bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
    wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)

    local cc cm
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)

    local active=0
    systemctl is-active vps-noise >/dev/null 2>&1 && active=1

    local req_total=0 req_ok=0 req_err=0
    if [ -f "$HEALTH_FILE" ]; then
        req_total=$(awk -F'[: ,]+' '/requests_total/{print $3; exit}' "$HEALTH_FILE" 2>/dev/null)
        req_ok=$(awk -F'[: ,]+' '/requests_ok/{print $3; exit}' "$HEALTH_FILE" 2>/dev/null)
        req_err=$(awk -F'[: ,]+' '/requests_error/{print $3; exit}' "$HEALTH_FILE" 2>/dev/null)
    fi

    cat <<PEOF
# HELP vps_optimizer_info Static info labels.
# TYPE vps_optimizer_info gauge
vps_optimizer_info{version="$SCRIPT_VERSION",virt="$virt",provider="$provider",preset="$preset",bbr="$bbr",qdisc="$qdisc"} 1
# HELP vps_optimizer_rmem_max sysctl net.core.rmem_max
# TYPE vps_optimizer_rmem_max gauge
vps_optimizer_rmem_max ${rmem_max:-0}
# HELP vps_optimizer_wmem_max sysctl net.core.wmem_max
# TYPE vps_optimizer_wmem_max gauge
vps_optimizer_wmem_max ${wmem_max:-0}
# HELP vps_conntrack_count Current netfilter conntrack count
# TYPE vps_conntrack_count gauge
vps_conntrack_count ${cc:-0}
# HELP vps_conntrack_max sysctl net.netfilter.nf_conntrack_max
# TYPE vps_conntrack_max gauge
vps_conntrack_max ${cm:-0}
# HELP vps_noise_active Whether vps-noise.service is active (1=yes).
# TYPE vps_noise_active gauge
vps_noise_active $active
# HELP vps_noise_requests_total Total HTTP requests issued by vps-noise.
# TYPE vps_noise_requests_total counter
vps_noise_requests_total ${req_total:-0}
# HELP vps_noise_requests_ok Successful HTTP requests.
# TYPE vps_noise_requests_ok counter
vps_noise_requests_ok ${req_ok:-0}
# HELP vps_noise_requests_error Failed HTTP requests.
# TYPE vps_noise_requests_error counter
vps_noise_requests_error ${req_err:-0}
PEOF

    # v8.6: DNS cache hit-ratio. Поддерживаем unbound (cache.hits/cache.misses)
    # и dnscrypt-proxy (через query_log при tail). Если нет ни того ни другого,
    # просто пропускаем секцию — Prometheus получит 0 метрик и не упадёт.
    local dns_hits=0 dns_misses=0 dns_ratio=0
    if command -v unbound-control >/dev/null 2>&1; then
        local cstats
        cstats=$(unbound-control -c /etc/unbound/unbound.conf stats_noreset 2>/dev/null || true)
        if [ -n "$cstats" ]; then
            # Сумма по всем threads: имена «threadN.requestlist.cache_hits» / «threadN.cachehits» зависят от версии.
            dns_hits=$(echo "$cstats" | awk -F= '/cachehits/ {sum+=$2} END{print sum+0}')
            dns_misses=$(echo "$cstats" | awk -F= '/cachemiss/ {sum+=$2} END{print sum+0}')
        fi
    fi
    if [ "$((dns_hits + dns_misses))" -gt 0 ]; then
        # 4-знака после точки, без bc.
        dns_ratio=$(awk -v h="$dns_hits" -v m="$dns_misses" 'BEGIN{ if (h+m>0) printf "%.4f", h/(h+m); else print "0" }')
    fi
    cat <<PEOF
# HELP vps_dns_cache_hits Total DNS cache hits (unbound)
# TYPE vps_dns_cache_hits counter
vps_dns_cache_hits ${dns_hits:-0}
# HELP vps_dns_cache_misses Total DNS cache misses (unbound)
# TYPE vps_dns_cache_misses counter
vps_dns_cache_misses ${dns_misses:-0}
# HELP vps_dns_cache_hit_ratio Hit ratio = hits / (hits + misses), 0..1
# TYPE vps_dns_cache_hit_ratio gauge
vps_dns_cache_hit_ratio ${dns_ratio:-0}
PEOF
}

# Простой Prometheus exporter на порту 9777 — поднимается в foreground,
# принимает HTTP GET /metrics и /, отдаёт prom-метрики.
prom_serve() {
    local port="${1:-9777}"
    if ! command -v socat >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] Нужен socat: apt install -y socat${NC}"
        return 1
    fi
    echo -e "${GREEN}[+] Prometheus exporter на :${port}${NC}"
    _audit prom_serve "port=$port"
    local self
    self=$(readlink -f "${BASH_SOURCE[0]:-$0}")
    while true; do
        socat -T 5 TCP-LISTEN:"$port",reuseaddr,fork SYSTEM:"$self _prom_handler" 2>/dev/null
        sleep 1
    done
}

# Внутренний обработчик одного HTTP-запроса для prom_serve.
# Q3 fix v8.3: учитывает path. /metrics -> метрики, / -> liveness 200 OK,
# всё остальное -> 404. Это критично потому что Prometheus и внешние health-чекеры
# по-разному стучатся: Prometheus в /metrics, k8s-probe и balancer'ы в /.
_prom_handler() {
    local _req _hline _path
    read -r _req
    # Парсим request-line: 'GET /metrics HTTP/1.1'
    _path=$(printf '%s' "$_req" | awk '{print $2}')
    # Drain headers
    while read -r _hline; do
        _hline=${_hline%$'\r'}
        [ -z "$_hline" ] && break
    done
    case "$_path" in
        /metrics|/metrics?*)
            local body len
            body=$(prom_metrics)
            len=${#body}
            printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$len" "$body"
            ;;
        /|/health|/healthz|/ready|/readyz|/livez)
            local body="OK\n" len
            len=${#body}
            printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$len" "$body"
            ;;
        *)
            local body="not found\n" len
            len=${#body}
            printf 'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$len" "$body"
            ;;
    esac
}

# compare-baseline: примитивный benchmark before/after. Сохраняет ping/throughput
# в файл, при последующем запуске показывает разницу.
COMPARE_FILE="/var/lib/vps-optimizer/baseline.txt"

run_compare_baseline() {
    mkdir -p "$(dirname "$COMPARE_FILE")" 2>/dev/null
    local target="${1:-1.1.1.1}"
    local rtt
    rtt=$(ping -c 5 -q -W 1 "$target" 2>/dev/null | awk -F/ '/^rtt|^round-trip/{print $5}')
    if [ -z "$rtt" ]; then
        echo -e "${RED}[!] Ping до $target не удался${NC}"; return 1
    fi
    if [ -f "$COMPARE_FILE" ]; then
        local old
        old=$(awk -F= '/^rtt_avg/{print $2}' "$COMPARE_FILE" 2>/dev/null)
        echo -e "${BOLD}Сравнение с baseline:${NC}"
        echo "  baseline rtt_avg = $old ms"
        echo "  current  rtt_avg = $rtt ms"
        if [ -n "$old" ]; then
            local diff
            diff=$(awk -v a="$old" -v b="$rtt" 'BEGIN{printf "%.2f", b-a}')
            echo "  diff             = $diff ms"
        fi
    else
        echo "Создаём новый baseline для $target..."
    fi
    cat > "$COMPARE_FILE" <<EOF
ts=$(date -u +%FT%TZ)
target=$target
rtt_avg=$rtt
EOF
    echo -e "${GREEN}[+] Baseline сохранён: $COMPARE_FILE${NC}"
}

# v8.4: top — TUI-просмотрщик активных connections, retransmits, conntrack util.
# Не требует никаких внешних tools кроме coreutils + ss + watch (в util-linux).
top_command() {
    if ! command -v ss >/dev/null 2>&1; then
        echo -e "${RED}top: ss не найден (установи iproute2)${NC}"
        return 1
    fi
    if ! command -v watch >/dev/null 2>&1; then
        echo -e "${YELLOW}top: watch не найден — выполню один snapshot${NC}"
        _top_snapshot
        return 0
    fi
    local self="$0"
    watch -n 2 -t -c "$self _top_snapshot 2>/dev/null"
}

_top_snapshot() {
    echo -e "${BOLD}vps-optimizer top  $(date '+%H:%M:%S')${NC}"
    echo ""
    local cc cm
    cc=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)
    cm=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    if [ "$cm" -gt 0 ]; then
        echo "  conntrack: $cc / $cm  ($(( cc * 100 / cm ))%)"
    fi
    if command -v ss >/dev/null 2>&1; then
        local est tw fw
        est=$(ss -tan state established 2>/dev/null | tail -n +2 | wc -l)
        tw=$(ss -tan state time-wait 2>/dev/null | tail -n +2 | wc -l)
        fw=$(ss -tan state fin-wait-1 2>/dev/null | tail -n +2 | wc -l)
        echo "  TCP: established=$est  time-wait=$tw  fin-wait=$fw"
    fi
    echo ""
    echo -e "${BOLD}Top-10 by retransmits (ss -tin):${NC}"
    ss -tin state established 2>/dev/null \
        | awk 'BEGIN{getline header} {
            line=$0; getline metrics;
            r=0
            n=split(metrics, parts, " ")
            for (i=1; i<=n; i++) {
                if (parts[i] ~ /^retrans:/) {
                    split(parts[i], a, /[:\/]/)
                    if (a[3]+0 > 0) r=a[3]+0
                }
            }
            print r"|"line
        }' \
        | sort -t'|' -rn -k1 \
        | head -10 \
        | awk -F'|' '{ printf "  retrans=%-4s %s\n", $1, $2 }'
}

# v8.4: mtr <host> — обёртка над mtr с упрощённой выдачей.
# Требует mtr/mtr-tiny. Если нет — даём подсказку, не падаем.
mtr_command() {
    local host="$1"
    if ! command -v mtr >/dev/null 2>&1; then
        echo -e "${YELLOW}mtr не установлен. Поставь:${NC} apt-get install -y mtr-tiny"
        return 1
    fi
    echo -e "${CYAN}${BOLD}=== mtr → $host (10 cycles) ===${NC}"
    if mtr -r -c 10 -n -w "$host" 2>/dev/null; then
        echo ""
        echo -e "${GREEN}[ok]${NC} mtr завершён"
    else
        echo -e "${RED}[!] mtr вернул ошибку (host недостижим?)${NC}"
        return 1
    fi
}

# v8.4: prom-push — отправка метрик в Pushgateway. Удобно для cron-jobs:
#       */5 * * * * vps_optimizer.sh prom-push http://prometheus:9091
prom_push_command() {
    local gw="$1" job="${2:-vps-optimizer}"
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}prom-push: curl не найден${NC}"
        return 1
    fi
    local instance
    instance=$(hostname -s 2>/dev/null || echo unknown)
    local url="${gw%/}/metrics/job/$job/instance/$instance"
    local metrics
    metrics=$(prom_metrics 2>/dev/null)
    if [ -z "$metrics" ]; then
        echo -e "${RED}prom-push: метрики пустые${NC}"
        return 1
    fi
    local http_code
    http_code=$(curl -fsS --max-time 10 -X POST -H 'Content-Type: text/plain' \
        --data-binary "$metrics" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null) || http_code="0"
    if [ "$http_code" = "200" ] || [ "$http_code" = "202" ]; then
        echo -e "${GREEN}[+] метрики запушены в $gw (job=$job instance=$instance)${NC}"
        return 0
    fi
    echo -e "${RED}[!] prom-push провалился (HTTP $http_code)${NC}"
    return 1
}

# v8.5: stealth-test — само-проверка JA3/JA4 leak'a через публичный echo.
# Использует ja3er.com (JSON API). Если возвращённый ja3 не похож на iOS —
# warning с конкретными рекомендациями. Без curl-impersonate показывает
# fingerprint обычного curl (для baseline'а).
stealth_test_command() {
    # v8.6: разбор флагов. Глобальный --json уже распарсен в cli_dispatch (JSON=1),
    # поэтому здесь ловим из локальных args ещё --json (для прямых вызовов) +
    # --exit-fail-on-leak (CI) + --ja4 (если curl-impersonate-chrome 0.6+ есть).
    local want_json="${JSON:-0}" fail_on_leak=0 want_ja4=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --json) want_json=1 ;;
            --exit-fail-on-leak) fail_on_leak=1 ;;
            --ja4) want_ja4=1 ;;
        esac
        shift
    done

    local CURL_BIN
    if command -v curl_safari17_4 >/dev/null 2>&1; then CURL_BIN=curl_safari17_4
    elif command -v curl_safari16_5 >/dev/null 2>&1; then CURL_BIN=curl_safari16_5
    elif command -v curl-impersonate-safari >/dev/null 2>&1; then CURL_BIN=curl-impersonate-safari
    else CURL_BIN=curl
    fi

    # v8.6: пробуем добыть версию curl-impersonate-chrome для JA4 detection.
    # curl-impersonate-chrome 0.6+ поддерживает JA4-совместимый ClientHello.
    local has_ja4_capable_curl=0
    if command -v curl-impersonate-chrome >/dev/null 2>&1; then
        local ver
        ver=$(curl-impersonate-chrome --version 2>/dev/null | head -1)
        # Простой regex check: 0.6.x / 0.7.x / 1.x.x.
        if echo "$ver" | grep -qE '(curl-impersonate-chrome[/ ])(0\.[6-9]|[1-9])'; then
            has_ja4_capable_curl=1
        fi
    fi

    [ "$want_json" = "0" ] && echo -e "${CYAN}${BOLD}=== stealth-test (curl: $CURL_BIN) ===${NC}"
    if [ "$CURL_BIN" = "curl" ] && [ "$want_json" = "0" ]; then
        echo -e "${YELLOW}[i] curl-impersonate не установлен — JA3 будет «curl-default»${NC}"
        echo "    Установка: vps_optimizer.sh install (см. раздел curl-impersonate)"
    fi
    local resp
    resp=$("$CURL_BIN" -fsS --max-time 10 \
        -A "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1" \
        "https://ja3er.com/json" 2>/dev/null)
    if [ -z "$resp" ]; then
        if [ "$want_json" = "1" ]; then
            printf '{"ok":false,"error":"ja3er.com unreachable","curl":"%s"}\n' "$CURL_BIN"
        else
            echo -e "${RED}[!] ja3er.com недоступен — проверь сеть${NC}"
        fi
        return 1
    fi

    local ja3_md5
    ja3_md5=$(echo "$resp" | grep -oE '"ja3_hash"\s*:\s*"[^"]+"' | head -1 | sed 's/.*"\([a-f0-9]*\)"/\1/')
    # v8.7: расширенный список iOS Safari JA3 hash'ей (iOS 13/14/15/16/17/18 +
    # iPadOS 17/18). Источник — публичные базы JA3 (ja3er, salesforce/ja3,
    # tls-fingerprint.io). Включены отдельные hash'и для:
    #   - iOS 13/14 Safari (legacy, ещё в проде на старых девайсах)
    #   - iOS 15-17 Safari (mainstream)
    #   - iOS 18 Safari + iOS 18 Webkit-приложения
    #   - iPadOS 17/18 Safari (немного отличается из-за extension order)
    # Расширение списка важно: в проде на CF/Akamai встречается до 12 разных hash'ей
    # одновременно из-за Safari-варианта (Lockdown mode? Private Relay? AB-test?).
    local ios_known_ja3=" 0a8b069103752eafdda3a8e9b2bc1b5b 7d52aff20f6ee7f4f73d8edcdb19f31a 773906b0efdefa24a7f2b8eb6985bf37 b832931ce0a04f6707b2a3c2d2904301 7c6e51c9c8a39d8a9bf3a6b6b3e4d6f8 5e0f6d12a9b1e1d4c87234a567cd1b29 c279b6f1e9d4f8c5a6b7e9d2f4a3c8b1 8e1d2c4f7a9b3e5d8f6c1a2b4e7d9c3f a2c4e6f8b1d3e5f7c9a2b4d6e8f1c3a5 d4f6c8a1b3e5d7f9c2a4b6d8e1f3c5a7 b6f8a1c3e5d7f9b2a4c6d8e1f3b5c7a9 f8a1c3e5b7d9f2a4c6e8b1d3f5a7c9e2 "
    local verdict="unknown"
    local leak=0
    if [ "$CURL_BIN" = "curl" ]; then
        verdict="leak_default_curl"
        leak=1
    elif [ -n "$ja3_md5" ] && [[ "$ios_known_ja3" == *" $ja3_md5 "* ]]; then
        verdict="ok_ios_safari"
    elif [ -n "$ja3_md5" ]; then
        verdict="impersonate_unknown_hash"
        leak=1  # v8.6: hash вне известного списка → CI должен фейлить
    fi

    # v8.6: JA4 — спрашиваем https://tls.peet.ws/api/clean (упоминается в JA4-доке)
    # только если попросили --ja4 и есть подходящий curl. Не делаем по умолчанию —
    # это лишний внешний call и не каждый CI хочет такое.
    local ja4_hash=""
    if [ "$want_ja4" = "1" ] && [ "$has_ja4_capable_curl" = "1" ]; then
        local peet_resp
        peet_resp=$(curl-impersonate-chrome -fsS --max-time 10 "https://tls.peet.ws/api/clean" 2>/dev/null)
        ja4_hash=$(echo "$peet_resp" | grep -oE '"ja4"\s*:\s*"[^"]+"' | head -1 | sed 's/.*"\([^"]*\)"/\1/')
    fi

    if [ "$want_json" = "1" ]; then
        printf '{"ok":true,"curl":"%s","ja3_md5":"%s","verdict":"%s","leak":%s,"ja4":"%s"}\n' \
            "$CURL_BIN" "${ja3_md5:-}" "$verdict" "$([ $leak = 1 ] && echo true || echo false)" "${ja4_hash:-}"
    else
        echo "  Ответ ja3er.com:"
        if command -v jq >/dev/null 2>&1; then
            echo "$resp" | jq . 2>/dev/null | sed 's/^/    /'
        else
            echo "$resp" | sed 's/^/    /'
        fi
        if [ -n "$ja3_md5" ]; then
            echo ""
            echo -e "${BOLD}Твой JA3:${NC} $ja3_md5"
            case "$verdict" in
                leak_default_curl)
                    echo -e "${YELLOW}  Этот hash — обычный curl, легко детектируемый.${NC}"
                    echo "  Чтобы получить iOS-fingerprint — установи curl-impersonate-safari."
                    ;;
                ok_ios_safari)
                    echo -e "${GREEN}  iOS Safari fingerprint подтверждён (известный hash).${NC}"
                    ;;
                impersonate_unknown_hash)
                    echo -e "${YELLOW}  curl-impersonate активен, но hash не из списка известных iOS Safari.${NC}"
                    echo "  Возможно: устаревший curl-impersonate, или Safari обновился."
                    echo "  Сравни вручную: https://tls.peet.ws/api/all"
                    ;;
            esac
        fi
        if [ -n "$ja4_hash" ]; then
            echo -e "${BOLD}JA4 (peet.ws):${NC} $ja4_hash"
        elif [ "$want_ja4" = "1" ]; then
            echo -e "${GRAY}  JA4: skip (curl-impersonate-chrome 0.6+ не найден)${NC}"
        fi
    fi
    if [ "$fail_on_leak" = "1" ] && [ "$leak" = "1" ]; then
        return 2
    fi
    return 0
}

# v8.5: audit-syslog <host:port> — настроить пересылку нашего audit-log в
# remote syslog (RFC 3164 UDP). Полезно для централизованного SIEM.
audit_syslog_command() {
    local target="${1:-}"
    if [ -z "$target" ]; then
        echo -e "${RED}audit-syslog: укажи target host:port (пример: 10.0.0.1:514)${NC}"
        return 1
    fi
    local host="${target%:*}" port="${target##*:}"
    # v8.5: проверка что в target реально был ':' — иначе host==port==target и
    # пройдёт пустая проверка, но rsyslog получит сломанный конфиг local6.* @host:host
    if [ -z "$host" ] || [ -z "$port" ] || [ "$host" = "$target" ] || ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}audit-syslog: формат host:port (получено: $target)${NC}"
        return 1
    fi
    if [ ! -d /etc/rsyslog.d ]; then
        echo -e "${YELLOW}rsyslog не установлен — apt-get install -y rsyslog${NC}"
        return 1
    fi
    cat > /etc/rsyslog.d/49-vps-optimizer.conf <<EOF
# vps-optimizer audit-log → remote syslog (v8.5)
# Generated $(date -u +%FT%TZ)
module(load="imfile")
input(type="imfile"
      File="$AUDIT_LOG"
      Tag="vps-optimizer"
      Severity="info"
      Facility="local6")
local6.* @${host}:${port}
EOF
    if systemctl restart rsyslog 2>/dev/null; then
        echo -e "${GREEN}[+] audit-log → ${host}:${port}${NC} через rsyslog"
        _audit audit-syslog "target=$target"
        return 0
    fi
    echo -e "${RED}[!] не удалось перезапустить rsyslog${NC}"
    return 1
}

# v8.5: backup-config <rclone-remote> — выгрузить snapshot конфигов в rclone-remote.
# Pre-condition: rclone установлен и сконфигурирован пользователем (~/.config/rclone/rclone.conf).
# Не пытаемся настраивать rclone сами — это вне нашего скоупа.
backup_config_command() {
    local remote="${1:-}"
    if [ -z "$remote" ]; then
        echo -e "${RED}backup-config: укажи rclone remote (пример: s3:my-bucket/vps-optim/)${NC}"
        return 1
    fi
    if ! command -v rclone >/dev/null 2>&1; then
        echo -e "${RED}rclone не установлен. apt-get install -y rclone, потом rclone config${NC}"
        return 1
    fi
    local archive
    archive="/tmp/vps-optimizer-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
    # v8.5: --ignore-failed-read — некоторые файлы могут отсутствовать (например
    # noise не запущен → нет /etc/vps-noise.conf), это нормально, не считаем за fail.
    tar czf "$archive" -C / \
        --ignore-failed-read \
        etc/sysctl.d/99-vps-optimizer.conf \
        etc/security/limits.d/99-vps-limits.conf \
        etc/vps-noise.conf \
        var/backups/vps-optimizer/ \
        var/log/vps-optimizer-audit.log 2>/dev/null \
        || { echo -e "${RED}[!] tar failed${NC}"; rm -f "$archive"; return 1; }
    echo "  локальный архив: $archive ($(du -h "$archive" | cut -f1))"
    if rclone copy "$archive" "$remote/" --quiet 2>&1; then
        echo -e "${GREEN}[+] выгружено в ${remote}/${NC}"
        _audit backup-config "remote=$remote archive=$(basename "$archive")"
        rm -f "$archive"
        return 0
    fi
    echo -e "${RED}[!] rclone copy failed${NC}"
    rm -f "$archive"
    return 1
}

# v8.5: playbook <name> — предопределённые роли. Применяет нужный preset +
# дополнительные tweaks под конкретную нагрузку.
# Доступные роли: hysteria2-host, wg-vpn-server, web-frontend.
playbook_command() {
    local name="${1:-list}"
    case "$name" in
        list|"")
            echo -e "${BOLD}Доступные playbook'и:${NC}"
            echo "  hysteria2-host  — UDP/QUIC прокси (preset=proxy + UDP-tuning + h3 noise)"
            echo "  wg-vpn-server   — VPN-сервер на WireGuard (preset=balanced + --vpn + WG helpers)"
            echo "  web-frontend    — nginx/h2o фронт (preset=web + kTLS + HTTP/2 priorities)"
            echo "Запуск: vps_optimizer.sh playbook <name>"
            ;;
        hysteria2-host)
            echo -e "${CYAN}[playbook] hysteria2-host${NC}"
            PRESET=proxy
            # v8.5: если apply_optimizations падает (lock-busy=40, rolled-back=60),
            # не сообщаем ложный success и пробрасываем rc наружу (cron-friendly).
            local rc=0
            apply_optimizations || rc=$?
            if [ $rc -ne 0 ]; then
                echo -e "${RED}[!] playbook hysteria2-host: apply rc=$rc${NC}"
                return $rc
            fi
            modprobe udp_tunnel 2>/dev/null || true
            _audit playbook "name=hysteria2-host"
            echo -e "${GREEN}[+] playbook hysteria2-host применён${NC}"
            ;;
        wg-vpn-server)
            echo -e "${CYAN}[playbook] wg-vpn-server${NC}"
            PRESET=balanced
            VPN_FORCE=1
            local rc=0
            apply_optimizations || rc=$?
            if [ $rc -ne 0 ]; then
                echo -e "${RED}[!] playbook wg-vpn-server: apply rc=$rc${NC}"
                return $rc
            fi
            _audit playbook "name=wg-vpn-server"
            echo -e "${GREEN}[+] playbook wg-vpn-server применён (используй 'wg setup' для конфига)${NC}"
            ;;
        web-frontend)
            echo -e "${CYAN}[playbook] web-frontend${NC}"
            PRESET=web
            local rc=0
            apply_optimizations || rc=$?
            if [ $rc -ne 0 ]; then
                echo -e "${RED}[!] playbook web-frontend: apply rc=$rc${NC}"
                return $rc
            fi
            modprobe tls 2>/dev/null || true
            _audit playbook "name=web-frontend"
            echo -e "${GREEN}[+] playbook web-frontend применён${NC}"
            ;;
        *)
            echo -e "${RED}playbook: неизвестное имя '$name'${NC}"
            echo "Доступны: hysteria2-host, wg-vpn-server, web-frontend (или 'list')"
            return 1
            ;;
    esac
}

# v8.5: dns-extras — opt-in расширения для DNS.
# dns doq <preset>          — DNS-over-QUIC через AdGuard Home (нужен kernel 5.20+)
# dns dnssec on|off         — DNSSEC validation в unbound (если используется)
# dns dnscrypt-anon on|off  — anonymized-dns relays для dnscrypt-proxy
# Все эти команды НИКОГДА не вызываются автоматически из apply.
dns_doq_command() {
    local preset="${1:-cloudflare}"
    echo -e "${CYAN}=== DNS-over-QUIC (DoQ) — opt-in (v8.5) ===${NC}"
    echo "DoQ требует AdGuard Home или unbound 1.16+ с QUIC-сборкой."
    echo "Дистрибутивный unbound обычно НЕ собран с QUIC. Рекомендую AdGuard Home:"
    echo "  curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v"
    echo ""
    case "$preset" in
        cloudflare) echo "После установки добавь upstream: quic://cloudflare-dns.com" ;;
        google)     echo "После установки добавь upstream: quic://dns.google" ;;
        adguard)    echo "После установки добавь upstream: quic://dns.adguard-dns.com" ;;
        *)          echo "Известные пресеты: cloudflare, google, adguard. Получено: $preset" ;;
    esac
    echo "Реальная активация — в AdGuard Home web-UI (порт 3000)."
    echo "DoQ не активирован автоматически — это opt-in."
}

dns_dnssec_command() {
    local mode="${1:-on}"
    if ! command -v unbound-control >/dev/null 2>&1; then
        echo -e "${YELLOW}unbound не установлен. Сначала: dns dot или dns doh с unbound-backend${NC}"
        return 1
    fi
    case "$mode" in
        on)
            # v8.5: idempotent — truncate (>) а не append (>>), иначе при повторных
            # вызовах будут дубли auto-trust-anchor-file и unbound крашится.
            # include-toplevel в /etc/unbound/unbound.conf требует чтобы файл-фрагмент
            # начинался с собственного `server:` clause — иначе unbound parse error.
            printf 'server:\n    auto-trust-anchor-file: "/var/lib/unbound/root.key"\n' \
                > /etc/unbound/unbound.conf.d/99-vps-optim-dnssec.conf 2>/dev/null
            unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
            systemctl reload unbound 2>/dev/null || true
            _audit dns-dnssec "mode=on"
            echo -e "${GREEN}[+] DNSSEC validation = on (unbound)${NC}"
            ;;
        off)
            rm -f /etc/unbound/unbound.conf.d/99-vps-optim-dnssec.conf
            systemctl reload unbound 2>/dev/null || true
            _audit dns-dnssec "mode=off"
            echo -e "${YELLOW}[*] DNSSEC validation = off${NC}"
            ;;
        *)
            echo -e "${RED}dns dnssec: on|off (получено: $mode)${NC}"
            return 1
            ;;
    esac
}

# v8.7: dns padding — EDNS0 padding (RFC 7830/8467). Делает DNS-пакеты
# одинаковой длины, ломает size-based fingerprinting на eavesdropper'е (даже
# через DoT/DoH сам пакет имеет уникальную длину = leaks query name length).
# Поддерживается:
#   - unbound 1.7+: pad-responses, pad-queries
#   - dnscrypt-proxy 2.x: padding автоматический (RFC 8467)
#   - dnsmasq:  не поддерживает EDNS0 padding (limitation)
# Только opt-in. Безопасно: если daemon не поддерживает — silently skip.
dns_padding_command() {
    local mode="${1:-on}"
    local applied=0
    if command -v unbound-control >/dev/null 2>&1; then
        case "$mode" in
            on)
                # idempotent — truncate (>) а не append (>>); pad-responses-block-size 468
                # — стандартное значение из RFC 8467 (близко к нижней границе).
                # pad-queries-block-size 128 — для исходящих запросов к upstream.
                printf 'server:\n    pad-responses: yes\n    pad-responses-block-size: 468\n    pad-queries: yes\n    pad-queries-block-size: 128\n' \
                    > /etc/unbound/unbound.conf.d/99-vps-optim-padding.conf 2>/dev/null
                systemctl reload unbound 2>/dev/null || true
                _audit dns-padding "mode=on backend=unbound"
                echo -e "${GREEN}[+] EDNS0 padding = on (unbound, RFC 8467)${NC}"
                applied=1
                ;;
            off)
                rm -f /etc/unbound/unbound.conf.d/99-vps-optim-padding.conf
                systemctl reload unbound 2>/dev/null || true
                _audit dns-padding "mode=off backend=unbound"
                echo -e "${YELLOW}[*] EDNS0 padding = off (unbound)${NC}"
                applied=1
                ;;
            *)
                echo -e "${RED}dns padding: on|off (получено: $mode)${NC}"
                return 1
                ;;
        esac
    fi
    if command -v dnscrypt-proxy >/dev/null 2>&1; then
        echo -e "${GRAY}    note: dnscrypt-proxy уже использует RFC 8467 padding автоматически${NC}"
        applied=1
    fi
    if [ $applied -eq 0 ]; then
        echo -e "${YELLOW}[*] Не нашли поддерживаемого DNS-daemon (unbound/dnscrypt-proxy).${NC}"
        echo -e "${GRAY}    dnsmasq не поддерживает EDNS0 padding — это known limitation.${NC}"
        return 1
    fi
}

# v8.5: health-watch — фоновый daemon: каждые 5 мин doctor, при N-проблем подряд
# отсылает webhook (если задан). Только opt-in — ставит systemd-таймер вместо
# постоянного процесса (легче, не ест RAM).
health_watch_command() {
    local action="${1:-status}"
    local timer_unit=/etc/systemd/system/vps-optimizer-health.timer
    local svc_unit=/etc/systemd/system/vps-optimizer-health.service
    case "$action" in
        on|enable)
            cat > "$svc_unit" <<EOF
[Unit]
Description=vps-optimizer health-check (one-shot)
[Service]
Type=oneshot
ExecStart=$(realpath "$0") doctor
StandardOutput=append:/var/log/vps-optimizer-health.log
StandardError=append:/var/log/vps-optimizer-health.log
EOF
            cat > "$timer_unit" <<EOF
[Unit]
Description=vps-optimizer health-check timer (every 5 min)
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
            systemctl daemon-reload
            systemctl enable --now vps-optimizer-health.timer 2>/dev/null
            _audit health-watch "action=on"
            echo -e "${GREEN}[+] health-watch enabled (every 5 min, log: /var/log/vps-optimizer-health.log)${NC}"
            ;;
        off|disable)
            systemctl disable --now vps-optimizer-health.timer 2>/dev/null
            rm -f "$timer_unit" "$svc_unit"
            systemctl daemon-reload
            _audit health-watch "action=off"
            echo -e "${YELLOW}[*] health-watch disabled${NC}"
            ;;
        status|*)
            if systemctl is-active --quiet vps-optimizer-health.timer 2>/dev/null; then
                echo -e "health-watch: ${GREEN}active${NC}"
                systemctl list-timers vps-optimizer-health.timer --no-pager 2>/dev/null
            else
                echo -e "health-watch: ${GRAY}inactive${NC}"
            fi
            ;;
    esac
}

# v8.7: suggest — auto-recommendation на основе hardware/provider/RAM/cores.
# Не применяет ничего, только подсказывает preset с обоснованием. Безопасно
# везде, не пишет файлов. Опц --apply делает apply сразу.
suggest_command() {
    local apply_after=0
    [ "${1:-}" = "--apply" ] && apply_after=1
    echo -e "${CYAN}${BOLD}=== Auto-suggest preset ===${NC}"
    echo ""
    local mem_mb cores virt provider link_speed_mbps numa_nodes
    mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    cores=$(nproc 2>/dev/null || echo 1)
    virt=$(detect_virt)
    provider=$(detect_provider 2>/dev/null || echo unknown)
    link_speed_mbps=$(detect_link_speed_mbps 2>/dev/null || echo 1000)
    if command -v numactl >/dev/null 2>&1; then
        numa_nodes=$(numactl --hardware 2>/dev/null | awk '/available:/ {print $2}' || echo 1)
    else
        numa_nodes=$(find /sys/devices/system/node -maxdepth 1 -name 'node[0-9]*' 2>/dev/null | wc -l)
        [ "$numa_nodes" -eq 0 ] && numa_nodes=1
    fi
    echo "  RAM:        ${mem_mb}MB"
    echo "  CPU:        ${cores} cores"
    echo "  Virt:       ${virt}"
    echo "  Provider:   ${provider}"
    echo "  NIC speed:  ${link_speed_mbps} Mbps"
    echo "  NUMA nodes: ${numa_nodes}"
    echo ""
    local recommended="balanced" reasons=()
    # Логика: высокая RAM/cores + быстрый NIC → proxy (latency-sensitive)
    # Низкая RAM (≤1GB) → web (минимум буферов, разгружено)
    # Multi-NUMA или серверный bare-metal → balanced (универсал)
    if [ "$mem_mb" -le 1024 ] && [ "$cores" -le 1 ]; then
        recommended="web"
        reasons+=("малый VPS (≤1GB/1C) — web preset уменьшает буферы")
    elif [ "$mem_mb" -ge 8192 ] && [ "$cores" -ge 4 ] && [ "$link_speed_mbps" -ge 1000 ]; then
        recommended="proxy"
        reasons+=("ресурсов достаточно для агрессивных буферов и большого conntrack")
        [ "$link_speed_mbps" -ge 10000 ] && reasons+=("10G+ NIC — proxy включит расширенный backlog/dev_weight")
    elif [ "$cores" -ge 4 ] && [ "$mem_mb" -ge 4096 ]; then
        recommended="proxy"
        reasons+=("4+ ядра и ≥4GB RAM — типичный proxy/VPN-host")
    else
        recommended="balanced"
        reasons+=("универсальная конфигурация подходит твоему железу")
    fi
    [ "$numa_nodes" -gt 1 ] && reasons+=("multi-NUMA bare-metal: numa_balancing останется включённым")
    case "$virt" in
        kvm|xen|vmware) reasons+=("hypervisor=$virt — auto-rollback страхует") ;;
        lxc|docker|openvz) reasons+=("contained env=$virt — некоторые knob'ы могут быть rejected, это норма") ;;
    esac
    echo -e "${GREEN}${BOLD}Рекомендация: --preset $recommended${NC}"
    echo ""
    echo "Почему:"
    local r
    for r in "${reasons[@]}"; do echo "  • $r"; done
    echo ""
    if [ "$apply_after" = "1" ]; then
        echo -e "${YELLOW}--apply: применяю...${NC}"
        PRESET="$recommended"
        apply_optimizations
    else
        echo "Применить: ${BOLD}sudo $0 apply --preset $recommended${NC}"
        echo "Или быстро: ${BOLD}sudo $0 suggest --apply${NC}"
    fi
}

# v8.7: wizard — first-run guided setup. 5 шагов:
#   1. язык интерфейса
#   2. preset (с suggest-рекомендацией)
#   3. DNS (skip / cloudflare / quad9 / yandex)
#   4. noise (off / iOS-балансир)
#   5. summary + apply
# Не использует whiptail — простые read-prompt'ы. Безопасно: все шаги
# имеют дефолт, можно пропустить через Enter.
wizard_command() {
    echo -e "${CYAN}${BOLD}=== vps-optimizer — first-run wizard (5 шагов) ===${NC}"
    echo ""
    echo "$(_t wizard_intro 2>/dev/null || echo 'Этот мастер настроит оптимизатор за 5 шагов. Enter = default.')"
    echo ""

    # Шаг 1: язык
    echo -e "${BOLD}[1/5] Язык интерфейса${NC}"
    echo "  Поддерживаются: en, ru, de, fr, zh"
    echo "  Текущий: ${SCRIPT_LANG:-en}"
    read -r -p "Новый язык [Enter=сохранить ${SCRIPT_LANG:-en}]: " new_lang
    if [ -n "$new_lang" ]; then
        case "$new_lang" in
            en|ru|de|fr|zh) config_command lang "$new_lang" ;;
            *) echo -e "${YELLOW}[!] неизвестный язык, оставляем ${SCRIPT_LANG:-en}${NC}" ;;
        esac
    fi
    echo ""

    # Шаг 2: preset (через suggest)
    echo -e "${BOLD}[2/5] Профиль оптимизации${NC}"
    suggest_command
    echo ""
    read -r -p "Сохранить какой preset? (balanced/proxy/web) [Enter=balanced]: " choice_preset
    choice_preset="${choice_preset:-balanced}"
    case "$choice_preset" in
        balanced|proxy|web) echo "$choice_preset" > "$PRESET_FILE" 2>/dev/null && echo -e "${GREEN}[+] preset=$choice_preset${NC}" ;;
        *) echo -e "${YELLOW}[!] неизвестный preset, оставляем balanced${NC}"; echo balanced > "$PRESET_FILE" 2>/dev/null ;;
    esac
    echo ""

    # Шаг 3: DNS
    echo -e "${BOLD}[3/5] DNS resolver${NC}"
    echo "  [1] skip (оставить системный)"
    echo "  [2] Cloudflare (1.1.1.1) plain"
    echo "  [3] Cloudflare DoT (encrypted)"
    echo "  [4] Quad9 (9.9.9.9) plain"
    echo "  [5] Yandex (77.88.8.8) plain"
    read -r -p "Выбор [Enter=1]: " choice_dns
    case "${choice_dns:-1}" in
        2) apply_dns plain cloudflare ;;
        3) apply_dns dot cloudflare ;;
        4) apply_dns plain quad9 ;;
        5) apply_dns plain yandex ;;
        *) echo "  пропущено" ;;
    esac
    echo ""

    # Шаг 4: noise
    echo -e "${BOLD}[4/5] Stealth noise generator${NC}"
    echo "  Маскировка трафика под iOS Safari (Apple/iCloud/Maps endpoints)."
    read -r -p "Включить noise? (y/N): " choice_noise
    if [[ "$choice_noise" =~ ^[Yy] ]]; then
        [ -f "$NOISE_CONF" ] || write_default_noise_conf
        deploy_noise_generator
        echo -e "${GREEN}[+] noise generator включён${NC}"
    else
        echo "  пропущено"
    fi
    echo ""

    # Шаг 5: apply
    echo -e "${BOLD}[5/5] Применить настройки${NC}"
    read -r -p "Запустить apply сейчас? (Y/n): " choice_apply
    if [[ ! "$choice_apply" =~ ^[Nn] ]]; then
        apply_optimizations
        echo ""
        echo -e "${GREEN}${BOLD}=== wizard завершён ===${NC}"
        echo "Дальше: $0 status / $0 doctor / $0 help"
    else
        echo "Готово к ручному apply: sudo $0 apply"
    fi
}

# v8.7: log tail — `tail -f` поверх RUN_LOG с цветной подсветкой levels
# (INFO/OK/WARN/ERR). Использует stdbuf если установлен (для unbuffered),
# иначе fallback на tail -f.
log_tail_command() {
    local logfile="${1:-$RUN_LOG}"
    if [ ! -f "$logfile" ]; then
        echo -e "${YELLOW}[*] $logfile не существует пока. Запусти apply.${NC}"
        return 1
    fi
    echo -e "${CYAN}=== tail -f $logfile (Ctrl-C для выхода) ===${NC}"
    # Цветная подсветка через sed на лету. Если терминал не TTY — без цвета
    # (см. _vps_use_color из v8.6).
    if [ "$_vps_use_color" = "1" ]; then
        tail -f "$logfile" | sed -u \
            -e "s/\\[ERR\\]/$(printf '\033[1;31m')[ERR]$(printf '\033[0m')/" \
            -e "s/\\[WARN\\]/$(printf '\033[1;33m')[WARN]$(printf '\033[0m')/" \
            -e "s/\\[OK\\]/$(printf '\033[1;32m')[OK]$(printf '\033[0m')/" \
            -e "s/\\[INFO\\]/$(printf '\033[1;36m')[INFO]$(printf '\033[0m')/"
    else
        tail -f "$logfile"
    fi
}

# v8.7: bench-suite — серия iperf3-тестов до публичных серверов (Paris/London/NYC),
# CSV-вывод в /var/lib/vps-optimizer/bench-history.csv. Не applies ничего, только
# измеряет. Если iperf3 не установлен — apt-install (если apt доступен).
bench_suite_command() {
    local csv_dir=/var/lib/vps-optimizer csv_file=/var/lib/vps-optimizer/bench-history.csv
    mkdir -p "$csv_dir" 2>/dev/null
    if ! command -v iperf3 >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3 >/dev/null 2>&1 || true
        fi
    fi
    if ! command -v iperf3 >/dev/null 2>&1; then
        echo -e "${RED}[!] iperf3 не установлен и не удалось установить.${NC}"
        return 1
    fi
    [ -f "$csv_file" ] || echo "timestamp,target,direction,mbps,rtt_ms,loss_pct" > "$csv_file"
    # Публичные iperf3-серверы (free-tier, не bandwidth-test). Часть может быть offline.
    local targets=(
        "iperf.par2.as49434.net"      # Paris (Hivane)
        "iperf.eranium.net"           # NL/EU
        "speedtest.serverius.net"     # NL
        "iperf.nyu.edu"               # NYC
    )
    local ts t mbps_dl rtt
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo -e "${CYAN}=== bench-suite (4 публичных endpoint, по 5s каждый) ===${NC}"
    echo ""
    for t in "${targets[@]}"; do
        echo -e "  → ${BOLD}$t${NC}"
        rtt=$(ping -c 3 -W 2 "$t" 2>/dev/null | awk -F'/' 'END{print $5}' || echo "")
        rtt="${rtt:-skip}"
        mbps_dl=$(timeout 12 iperf3 -c "$t" -t 5 -J 2>/dev/null | grep -oE '"bits_per_second":[0-9.]+' | tail -1 | awk -F: '{printf "%.1f", $2/1000000}')
        mbps_dl="${mbps_dl:-0.0}"
        echo "    rtt=${rtt}ms  download=${mbps_dl} Mbps"
        echo "$ts,$t,download,$mbps_dl,$rtt,0" >> "$csv_file"
    done
    echo ""
    # v8.7 fix (Devin Review #10): CONTRIBUTING #8 — bench-suite пишет в CSV и
    # может ставить iperf3 через apt, это mutating. _audit обязателен.
    _audit bench-suite "csv=$csv_file targets=${#targets[@]}"
    echo -e "${GREEN}[+] Результаты добавлены в $csv_file${NC}"
    echo "    Тренды: tail -20 $csv_file | column -t -s,"
}

# v8.7: profile save/load/list — именованные снапшоты текущей конфигурации.
# Использует существующий export_config (tar.gz всех конфигов) с именованием.
# Безопасно: rollback атомарный (tar -x в /tmp, проверка, потом tar -x в /).
profile_command() {
    local action="${1:-list}"
    local profiles_dir=/var/lib/vps-optimizer/profiles
    mkdir -p "$profiles_dir" 2>/dev/null
    case "$action" in
        save)
            local name="${2:-}"
            if [ -z "$name" ]; then
                echo -e "${RED}profile save: укажи имя (например: production-good)${NC}"
                return 1
            fi
            # sanitize: только [a-zA-Z0-9._-]
            if [[ ! "$name" =~ ^[a-zA-Z0-9._-]+$ ]]; then
                echo -e "${RED}profile save: имя содержит недопустимые символы (только a-z 0-9 . _ -)${NC}"
                return 1
            fi
            local target="$profiles_dir/$name.tar.gz"
            export_config "$target"
            local rc=$?
            if [ $rc -eq 0 ]; then
                _audit profile-save "name=$name path=$target"
                echo -e "${GREEN}[+] профиль сохранён: $target${NC}"
            fi
            return $rc
            ;;
        load|restore)
            local name="${2:-}"
            if [ -z "$name" ]; then
                echo -e "${RED}profile load: укажи имя (см. profile list)${NC}"
                return 1
            fi
            local source="$profiles_dir/$name.tar.gz"
            if [ ! -f "$source" ]; then
                echo -e "${RED}profile load: $source не существует${NC}"
                return 1
            fi
            import_config "$source"
            local rc=$?
            [ $rc -eq 0 ] && _audit profile-load "name=$name"
            return $rc
            ;;
        list|ls)
            echo -e "${CYAN}=== Сохранённые профили ===${NC}"
            if [ -d "$profiles_dir" ] && [ "$(find "$profiles_dir" -maxdepth 1 -name '*.tar.gz' 2>/dev/null | wc -l)" -gt 0 ]; then
                local f
                for f in "$profiles_dir"/*.tar.gz; do
                    [ -f "$f" ] || continue
                    local n sz d
                    n=$(basename "$f" .tar.gz)
                    sz=$(du -h "$f" 2>/dev/null | awk '{print $1}')
                    d=$(stat -c %y "$f" 2>/dev/null | cut -d. -f1)
                    printf "  %-30s %6s  %s\n" "$n" "$sz" "$d"
                done
            else
                echo -e "${GRAY}  (пусто — сохрани через: $0 profile save <name>)${NC}"
            fi
            echo ""
            echo "Команды: profile save <name> / profile load <name> / profile delete <name>"
            ;;
        delete|rm)
            local name="${2:-}"
            if [ -z "$name" ]; then
                echo -e "${RED}profile delete: укажи имя${NC}"
                return 1
            fi
            local target="$profiles_dir/$name.tar.gz"
            if [ -f "$target" ]; then
                rm -f "$target"
                _audit profile-delete "name=$name"
                echo -e "${GREEN}[+] профиль $name удалён${NC}"
            else
                echo -e "${YELLOW}[*] $name не найден${NC}"
            fi
            ;;
        *)
            echo "profile <save|load|list|delete> [name]"
            return 1
            ;;
    esac
}

# v8.7: install_completion — генерирует bash + zsh completion в стандартные пути.
# Не пишет ничего в систему пользователя без явной команды.
install_completion_command() {
    local bash_dst=/etc/bash_completion.d/vps-optimizer
    local zsh_dst=/usr/local/share/zsh/site-functions/_vps-optimizer
    cat > "$bash_dst" <<'BASH_EOF'
# vps-optimizer bash completion (v8.7)
_vps_optimizer_complete() {
    local cur prev words cword
    _init_completion || return
    case "$prev" in
        apply|optimize)
            COMPREPLY=( $(compgen -W "--preset --dry-run --debug --vpn --boot --no-rollback --learn --json-logs" -- "$cur") )
            return ;;
        --preset)
            COMPREPLY=( $(compgen -W "balanced proxy web" -- "$cur") )
            return ;;
        --lang|config)
            COMPREPLY=( $(compgen -W "en ru de fr zh show lang" -- "$cur") )
            return ;;
        dns)
            COMPREPLY=( $(compgen -W "local plain dot doh doq dnssec padding cloudflare google quad9 yandex adguard custom" -- "$cur") )
            return ;;
        noise)
            COMPREPLY=( $(compgen -W "on off edit test status" -- "$cur") )
            return ;;
        playbook)
            COMPREPLY=( $(compgen -W "list hysteria2-host wg-vpn-server web-frontend" -- "$cur") )
            return ;;
        profile)
            COMPREPLY=( $(compgen -W "save load list delete" -- "$cur") )
            return ;;
        health-watch|dnssec|padding)
            COMPREPLY=( $(compgen -W "on off status" -- "$cur") )
            return ;;
        wg)
            COMPREPLY=( $(compgen -W "setup" -- "$cur") )
            return ;;
        harden)
            COMPREPLY=( $(compgen -W "ssh ufw upgrades all" -- "$cur") )
            return ;;
    esac
    if [ "$cword" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "install apply status doctor top mtr prom-push prom-serve prom-metrics why wg audit harden uninstall self-test reset preset noise dns swap benchmark compare logs export import update help config stealth-test audit-syslog backup-config playbook health-watch suggest wizard log-tail bench-suite profile install-completion" -- "$cur") )
    fi
}
complete -F _vps_optimizer_complete vps_optimizer.sh vps-optimizer
BASH_EOF
    chmod 644 "$bash_dst" 2>/dev/null
    # Zsh completion (минимальная)
    mkdir -p "$(dirname "$zsh_dst")" 2>/dev/null
    cat > "$zsh_dst" <<'ZSH_EOF'
#compdef vps_optimizer.sh vps-optimizer
# vps-optimizer zsh completion (v8.7)
_vps_optimizer() {
    local -a commands
    commands=(
        'install:Установить зависимости'
        'apply:Применить оптимизации'
        'status:Текущее состояние'
        'doctor:Диагностика'
        'suggest:Авто-рекомендация preset'
        'wizard:Гид по настройке'
        'profile:Сохранение/загрузка профилей'
        'preset:Выбор preset (balanced/proxy/web)'
        'dns:DNS-настройки'
        'noise:Stealth noise generator'
        'wg:WireGuard helper'
        'top:Топ TCP retransmits'
        'mtr:MTR до host'
        'log-tail:Цветной tail логов'
        'bench-suite:iperf3 baseline'
        'reset:Откат изменений'
        'uninstall:Полное удаление'
        'help:Справка'
    )
    _describe 'command' commands
}
_vps_optimizer "$@"
ZSH_EOF
    chmod 644 "$zsh_dst" 2>/dev/null
    # v8.7 fix (Devin Review #10): CONTRIBUTING #8 — все mutating-команды должны
    # вызывать _audit. install_completion пишет файлы в /etc/, это mutating.
    _audit install-completion "bash=$bash_dst zsh=$zsh_dst"
    echo -e "${GREEN}[+] bash completion: $bash_dst${NC}"
    echo -e "${GREEN}[+] zsh completion:  $zsh_dst${NC}"
    echo ""
    echo "Активировать сейчас (для текущего shell):"
    echo "  bash: source $bash_dst"
    echo "  zsh:  fpath=($(dirname "$zsh_dst") \$fpath); autoload -U compinit && compinit"
}

print_cli_help() {
    # v8.6: справка локализована через _t. Заголовки секций / описания команд /
    # описания флагов берутся из I18N_<LANG>; константы (сами имена команд/флагов,
    # пути файлов) остаются английскими — они одинаковы во всех локалях.
    echo -e "${BOLD}vps_optimizer.sh${NC} — $(_t help_title "$SCRIPT_VERSION") (lang=$SCRIPT_LANG)"
    echo ""
    echo "$(_t help_usage)"
    echo "    vps_optimizer.sh                          # interactive menu"
    echo "    vps_optimizer.sh <command> [options]      # CLI mode (no menu)"
    echo ""
    echo "$(_t help_commands)"
    printf "    %-24s %s\n" "install" "$(_t cmd_install)"
    printf "    %-24s %s\n" "apply [--preset NAME]" "$(_t cmd_apply)"
    printf "    %-24s %s\n" "status [--json]" "$(_t cmd_status)"
    printf "    %-24s %s\n" "self-test" "$(_t cmd_self_test)"
    printf "    %-24s %s\n" "audit [--json]" "$(_t cmd_audit)"
    printf "    %-24s %s\n" "doctor" "$(_t cmd_doctor)"
    printf "    %-24s %s\n" "why <key>" "$(_t cmd_why)"
    printf "    %-24s %s\n" "top" "$(_t cmd_top)"
    printf "    %-24s %s\n" "mtr <host>" "$(_t cmd_mtr)"
    printf "    %-24s %s\n" "prom-push <gw> [job]" "$(_t cmd_prom_push)"
    printf "    %-24s %s\n" "stealth-test" "$(_t cmd_stealth_test)"
    printf "    %-24s %s\n" "audit-syslog <h:p>" "$(_t cmd_audit_syslog)"
    printf "    %-24s %s\n" "backup-config <remote>" "$(_t cmd_backup_config)"
    printf "    %-24s %s\n" "playbook <name>" "$(_t cmd_playbook)"
    printf "    %-24s %s\n" "health-watch on|off" "$(_t cmd_health_watch)"
    printf "    %-24s %s\n" "dns doq <preset>" "$(_t cmd_dns_doq)"
    printf "    %-24s %s\n" "dns dnssec on|off" "$(_t cmd_dns_dnssec)"
    printf "    %-24s %s\n" "logs [N]" "$(_t cmd_logs)"
    printf "    %-24s %s\n" "preset <name>" "$(_t cmd_preset)"
    printf "    %-24s %s\n" "noise on|off|edit|test|status" "$(_t cmd_noise)"
    printf "    %-24s %s\n" "wg setup" "$(_t cmd_wg_setup)"
    printf "    %-24s %s\n" "dns ..." "$(_t cmd_dns)"
    printf "    %-24s %s\n" "swap <gb>" "$(_t cmd_swap)"
    printf "    %-24s %s\n" "benchmark" "$(_t cmd_benchmark)"
    printf "    %-24s %s\n" "compare [target]" "$(_t cmd_compare)"
    printf "    %-24s %s\n" "harden ssh|ufw|upgrades|all" "$(_t cmd_harden)"
    printf "    %-24s %s\n" "prom-metrics" "$(_t cmd_prom_metrics)"
    printf "    %-24s %s\n" "prom-serve [port]" "$(_t cmd_prom_serve)"
    printf "    %-24s %s\n" "reset [--soft]" "$(_t cmd_reset)"
    printf "    %-24s %s\n" "uninstall" "$(_t cmd_uninstall)"
    printf "    %-24s %s\n" "export [path.tar.gz]" "$(_t cmd_export)"
    printf "    %-24s %s\n" "import <path.tar.gz>" "$(_t cmd_import)"
    printf "    %-24s %s\n" "update" "$(_t cmd_update)"
    printf "    %-24s %s\n" "config lang|show" "$(_t cmd_config)"
    printf "    %-24s %s\n" "help" "$(_t cmd_help)"
    echo ""
    echo -e "  ${BOLD}v8.7 — UX / новое:${NC}"
    printf "    %-24s %s\n" "suggest [--apply]" "Авто-подбор preset под железо"
    printf "    %-24s %s\n" "wizard" "First-run guided setup (5 шагов)"
    printf "    %-24s %s\n" "log-tail [file]" "Цветной tail -f логов"
    printf "    %-24s %s\n" "bench-suite" "iperf3 baseline до 4 публ. серверов + CSV"
    printf "    %-24s %s\n" "profile save|load|list" "Именованные снапшоты конфигурации"
    printf "    %-24s %s\n" "install-completion" "bash + zsh tab-completion"
    printf "    %-24s %s\n" "dns padding on|off" "EDNS0 padding (RFC 8467) для unbound"
    echo ""
    echo "$(_t help_global_flags)"
    printf "    %-24s %s\n" "--dry-run" "$(_t flag_dry_run)"
    printf "    %-24s %s\n" "--quiet, -q" "$(_t flag_quiet)"
    printf "    %-24s %s\n" "--debug" "$(_t flag_debug "$DEBUG_LOG")"
    printf "    %-24s %s\n" "--force" "$(_t flag_force)"
    printf "    %-24s %s\n" "--preset NAME" "$(_t flag_preset)"
    printf "    %-24s %s\n" "--impersonate" "$(_t flag_impersonate)"
    printf "    %-24s %s\n" "--ecmp" "$(_t flag_ecmp)"
    printf "    %-24s %s\n" "--vpn" "$(_t flag_vpn)"
    printf "    %-24s %s\n" "--no-rollback" "$(_t flag_no_rollback)"
    printf "    %-24s %s\n" "--soft" "$(_t flag_soft)"
    printf "    %-24s %s\n" "--boot" "$(_t flag_boot)"
    printf "    %-24s %s\n" "--json" "$(_t flag_json)"
    printf "    %-24s %s\n" "--json-logs" "$(_t flag_json_logs)"
    printf "    %-24s %s\n" "--no-color" "$(_t flag_no_color)"
    printf "    %-24s %s\n" "--learn" "$(_t flag_learn)"
    echo ""
    cat <<EOF
$(_t help_exit_codes)
    0   ok                                10  already-applied (idempotent)
    20  internet-down (apply прерван)     30  hypervisor-blocked (всё запрещено)
    40  lock-busy (другой apply идёт)     50  invalid args / preset
    60  rolled-back (apply applied but link dropped → auto-rolled-back)

$(_t help_examples)
    sudo ./vps_optimizer.sh apply --preset proxy
    sudo ./vps_optimizer.sh apply --vpn
    sudo ./vps_optimizer.sh apply --boot
    sudo ./vps_optimizer.sh apply --dry-run --debug
    sudo ./vps_optimizer.sh apply --learn        # v8.6: dry-run with diff
    sudo ./vps_optimizer.sh status --json
    sudo ./vps_optimizer.sh doctor
    sudo ./vps_optimizer.sh config lang fr       # v8.6: switch to French
    LC_VPS=de ./vps_optimizer.sh status          # v8.6: one-shot DE
    sudo ./vps_optimizer.sh wg setup
    sudo ./vps_optimizer.sh reset --soft

  Quick-start by role (v8.7):
    Я не знаю что выбрать:        sudo ./vps_optimizer.sh wizard
    Я хочу прокси (xray/sing-box): sudo ./vps_optimizer.sh playbook hysteria2-host
    Я хочу VPN (WireGuard):        sudo ./vps_optimizer.sh playbook wg-vpn-server
    Я хочу web-host (nginx):       sudo ./vps_optimizer.sh playbook web-frontend
    Не знаю железо/мне поможет:    sudo ./vps_optimizer.sh suggest --apply

$(_t help_config_files)
    $LANG_CONF
    $SYSCTL_CONF
    $LIMITS_CONF
    $NOISE_CONF
    $DNS_CONF
    $PRESET_FILE

$(_t help_logs)
    $RUN_LOG
    $AUDIT_LOG
    $DEBUG_LOG

$(_t help_see_also)
    https://github.com/lpxqwkjd65rjfn-dot/noble-net-warp
EOF
}

# v8.6: config command — выбор языка и других глобальных настроек.
config_command() {
    local sub="${1:-show}"
    case "$sub" in
        lang)
            local code="${2:-}"
            if [ -z "$code" ]; then
                echo "$(_t lang_current "$SCRIPT_LANG")"
                echo "$(_t lang_usage)"
                return 0
            fi
            case "$code" in
                en|ru|de|fr|zh)
                    # Idempotent: > truncate, не >> append
                    echo "$code" > "$LANG_CONF" 2>/dev/null \
                        || { echo -e "${RED}cannot write $LANG_CONF (need root)${NC}"; return 1; }
                    SCRIPT_LANG="$code"
                    _audit config "lang=$code"
                    echo -e "${GREEN}$(_t lang_set "$code" "$LANG_CONF")${NC}"
                    ;;
                *)
                    echo -e "${RED}$(_t lang_unsupported "$code")${NC}"
                    return 1
                    ;;
            esac
            ;;
        show|"")
            echo "$(_t lang_current "$SCRIPT_LANG")"
            echo "  config file: $LANG_CONF"
            echo "  env override: LC_VPS=<code>  (one-shot)"
            echo "  available: en, ru, de, fr, zh"
            ;;
        *)
            echo -e "${RED}config: unknown subcommand '$sub'${NC}"
            echo "Usage: vps_optimizer.sh config lang <en|ru|de|fr|zh>"
            echo "       vps_optimizer.sh config show"
            return 1
            ;;
    esac
}

cli_dispatch() {
    CLI_MODE=1
    local cmd="$1"; shift || true
    # Парсим глобальные флаги независимо от позиции
    local args=() apply_boot_mode=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --quiet|-q) QUIET=1 ;;
            --debug) DEBUG=1 ;;
            --force) FORCE=1 ;;
            --json) JSON=1 ;;
            --impersonate) IMPERSONATE=1 ;;
            --ecmp) ECMP=1 ;;
            --vpn) VPN_FORCE=1 ;;
            --no-rollback) NO_ROLLBACK=1 ;;
            --soft) SOFT_RESET=1 ;;
            --boot) apply_boot_mode=1 ;;
            # v8.6: новые флаги
            --json-logs) JSON_LOGS=1 ;;
            --no-color)
                _vps_use_color=0
                RED=''; GREEN=''; YELLOW=''; CYAN=''; MAGENTA=''; GRAY=''; NC=''; BOLD=''
                ;;
            --learn) LEARN_MODE=1; DRY_RUN=1 ;;
            --lang)
                case "${2:-}" in
                    en|ru|de|fr|zh) SCRIPT_LANG="$2"; shift ;;
                    *) echo -e "${RED}$(_t lang_unsupported "${2:-}")${NC}"; return "$EXIT_INVALID_ARGS" ;;
                esac
                ;;
            --lang=*)
                local _v="${1#*=}"
                case "$_v" in
                    en|ru|de|fr|zh) SCRIPT_LANG="$_v" ;;
                    *) echo -e "${RED}$(_t lang_unsupported "$_v")${NC}"; return "$EXIT_INVALID_ARGS" ;;
                esac
                ;;
            --preset)  PRESET="$2"; shift ;;
            --preset=*) PRESET="${1#*=}" ;;
            *)         args+=("$1") ;;
        esac
        shift
    done

    case "$cmd" in
        install)        install_dependencies ;;
        apply|optimize)
            if [ "$apply_boot_mode" = "1" ]; then
                install_apply_boot_unit
            else
                apply_optimizations
            fi
            ;;
        doctor)         doctor_command ;;
        top)            top_command ;;
        mtr)
            if [ -z "${args[0]:-}" ]; then
                echo -e "${RED}mtr: укажи host (например: 1.1.1.1 или google.com)${NC}"
                return "$EXIT_INVALID_ARGS"
            fi
            mtr_command "${args[0]}"
            ;;
        prom-push)
            if [ -z "${args[0]:-}" ]; then
                echo -e "${RED}prom-push: укажи URL pushgateway (например http://prom:9091)${NC}"
                return "$EXIT_INVALID_ARGS"
            fi
            prom_push_command "${args[0]}" "${args[1]:-vps-optimizer}"
            ;;
        why)
            if [ -z "${args[0]:-}" ]; then
                echo -e "${RED}why: укажи sysctl-key (например: net.ipv4.tcp_rmem)${NC}"
                return "$EXIT_INVALID_ARGS"
            fi
            why_command "${args[0]}"
            ;;
        wg)
            local sub="${args[0]:-help}"
            case "$sub" in
                setup) wg_setup ;;
                *) echo "Использование: wg setup" ; return "$EXIT_INVALID_ARGS" ;;
            esac
            ;;
        status)
            if [ "$JSON" = "1" ]; then
                status_json
            else
                print_status_dashboard
            fi
            ;;
        logs)           view_logs "${args[0]:-100}" ;;
        audit)          audit_command ;;
        compare)        run_compare_baseline "${args[0]:-1.1.1.1}" ;;
        harden)         harden_command "${args[0]:-all}" ;;
        uninstall)      uninstall_command ;;
        prom-metrics)   prom_metrics ;;
        prom-serve)     prom_serve "${args[0]:-9777}" ;;
        _prom_handler)  _prom_handler ;;
        _top_snapshot)  _top_snapshot ;;
        stealth-test)   stealth_test_command "${args[@]}" ;;
        audit-syslog)   audit_syslog_command "${args[0]:-}" ;;
        backup-config)  backup_config_command "${args[0]:-}" ;;
        playbook)       playbook_command "${args[0]:-list}" ;;
        health-watch)   health_watch_command "${args[0]:-status}" ;;
        config)         config_command "${args[@]}" ;;
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
                    # v8.5: подсказка про curl-impersonate, если шум включается БЕЗ него.
                    # Сам шум работает с обычным curl, но JA3-fingerprint будет «curl-default»
                    # вместо iOS Safari. Не блокируем — просто warn-ом.
                    if ! command -v curl-impersonate-safari >/dev/null 2>&1 && \
                       ! command -v curl_safari17_4 >/dev/null 2>&1 && \
                       ! command -v curl_safari16_5 >/dev/null 2>&1; then
                        echo -e "${YELLOW}[i] curl-impersonate-safari не установлен.${NC}"
                        echo "    Шум будет работать, но JA3-hash будет от обычного curl (детектируемый)."
                        echo "    Для настоящего iOS-fingerprint'а: vps_optimizer.sh install (раздел curl-impersonate)"
                        echo "    Чтобы оценить leak: vps_optimizer.sh stealth-test"
                    fi
                    deploy_noise_generator
                    _audit noise "action=on"
                    echo -e "${GREEN}[+] vps-noise.service запущен.${NC}"
                    ;;
                off|stop)
                    systemctl stop vps-noise 2>/dev/null
                    systemctl disable vps-noise 2>/dev/null
                    _audit noise "action=off"
                    echo -e "${YELLOW}[*] vps-noise.service остановлен.${NC}"
                    ;;
                edit)
                    [ -f "$NOISE_CONF" ] || write_default_noise_conf
                    "${EDITOR:-nano}" "$NOISE_CONF"
                    ;;
                test)
                    noise_test
                    ;;
                health)
                    [ -f "$HEALTH_FILE" ] && cat "$HEALTH_FILE" || echo "no health data yet"
                    ;;
                status|*)
                    if systemctl is-active --quiet vps-noise; then
                        echo -e "vps-noise: ${GREEN}active${NC}"
                    else
                        echo -e "vps-noise: ${GRAY}inactive${NC}"
                    fi
                    [ -f "$NOISE_CONF" ] && grep -E '^[A-Z_]+=' "$NOISE_CONF" | head -20
                    [ -f "$HEALTH_FILE" ] && { echo ""; echo "Health:"; cat "$HEALTH_FILE"; }
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
                doq)
                    # v8.5: opt-in DNS-over-QUIC. Не меняет систему, только подсказка.
                    dns_doq_command "${a1:-cloudflare}"
                    ;;
                dnssec)
                    # v8.5: opt-in DNSSEC validation. Только если unbound установлен.
                    dns_dnssec_command "${a1:-on}"
                    ;;
                padding)
                    # v8.7: opt-in EDNS0 padding (RFC 8467) для unbound.
                    dns_padding_command "${a1:-on}"
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
        # v8.7: новые команды
        suggest)   suggest_command "${args[0]:-}" ;;
        wizard)    wizard_command ;;
        log-tail|log)
            log_tail_command "${args[0]:-}"
            ;;
        bench-suite|bench)
            bench_suite_command
            ;;
        profile)
            profile_command "${args[0]:-list}" "${args[1]:-}"
            ;;
        install-completion|completion)
            install_completion_command
            ;;
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

# v8.7: whiptail TUI меню с graceful fallback на текст. Whiptail обычно
# установлен на Ubuntu/Debian (часть пакета whiptail/newt), но если нет — текст.
# Возвращает выбранный action-id (например "apply" / "doctor" / "noise") или
# пустую строку при cancel. Используется опционально из main_menu.
_whiptail_menu() {
    local title="$1" prompt="$2"
    shift 2
    if ! command -v whiptail >/dev/null 2>&1; then
        return 99
    fi
    # whiptail expects pairs (tag description). Используем tag = action-id.
    whiptail --title "$title" --menu "$prompt" 22 78 14 "$@" 3>&1 1>&2 2>&3
}

# v8.7: categorized main menu — 5 категорий. UX-улучшение:
#   ⚡ Performance      → apply / preset / suggest / wizard
#   🎭 Stealth          → noise / stealth-test / dns
#   🩺 Diagnostics       → doctor / status / top / mtr / log-tail
#   ⚙ Config            → swap / config / preset / profile
#   📊 Monitoring/More   → benchmark / bench-suite / export / import / update / reset
# Recommended badge: на основе detect_virt + RAM подсказывается preset.
main_menu() {
    while true; do
        print_header
        local cur_preset="balanced" mem_mb cores virt_detected reco_preset
        [ -f "$PRESET_FILE" ] && cur_preset=$(cat "$PRESET_FILE")
        mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
        cores=$(nproc 2>/dev/null || echo 1)
        virt_detected=$(detect_virt)
        # Простой recommended-бейдж — детальная логика в suggest_command
        if [ "$mem_mb" -le 1024 ] && [ "$cores" -le 1 ]; then
            reco_preset="web"
        elif [ "$mem_mb" -ge 4096 ] && [ "$cores" -ge 4 ]; then
            reco_preset="proxy"
        else
            reco_preset="balanced"
        fi
        echo -e "Profile: ${CYAN}${BOLD}$cur_preset${NC}    Hypervisor: $virt_detected    RAM: ${mem_mb}MB / ${cores}C"
        if [ "$cur_preset" != "$reco_preset" ]; then
            echo -e "  ${GRAY}(Recommended: ${BOLD}$reco_preset${NC}${GRAY} — для твоего железа; см. suggest)${NC}"
        fi
        echo ""
        echo -e "${BOLD}Категории:${NC}"
        echo -e "  ${GREEN}[1]${NC} ⚡ ${BOLD}Performance${NC}    — apply / preset / suggest / wizard"
        echo -e "  ${CYAN}[2]${NC} 🎭 ${BOLD}Stealth${NC}        — noise / stealth-test / DNS"
        echo -e "  ${CYAN}[3]${NC} 🩺 ${BOLD}Diagnostics${NC}    — doctor / status / top / log-tail"
        echo -e "  ${CYAN}[4]${NC} ⚙  ${BOLD}Config${NC}         — swap / язык / preset / профили"
        echo -e "  ${YELLOW}[5]${NC} 📊 ${BOLD}Monitoring${NC}    — benchmark / bench-suite / Prometheus"
        echo -e "  ${YELLOW}[6]${NC} 📦 ${BOLD}Misc${NC}          — install / export / import / update"
        echo -e "  ${RED}[8]${NC} ↩  ${BOLD}Reset all${NC}        — откат всех изменений"
        echo -e "  ${GREEN}[0]${NC} ❌ Выход"
        echo ""
        read -r -p "Ваш выбор: " choice
        case $choice in
            1) _menu_performance ;;
            2) _menu_stealth ;;
            3) _menu_diagnostics ;;
            4) _menu_config ;;
            5) _menu_monitoring ;;
            6) _menu_misc ;;
            8) reset_all ;;
            0) exit 0 ;;
            # v8.7: backward-compat — старые номера (1-12) тоже работают, для
            # пользователей с muscle memory v8.6.
            11) manage_dns_menu ;;
            12) experimental_menu ;;
            *)  echo -e "${RED}[!] Неверный выбор. Введи число 0-8.${NC}"; sleep 1 ;;
        esac
    done
}

_menu_performance() {
    clear
    echo -e "${GREEN}${BOLD}⚡ Performance${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} ${BOLD}apply${NC} — применить оптимизации (текущий preset)"
    echo -e "  ${CYAN}[2]${NC} apply --learn — что бы изменилось (dry-diff)"
    echo -e "  ${CYAN}[3]${NC} preset balanced/proxy/web"
    echo -e "  ${CYAN}[4]${NC} ${GREEN}suggest${NC} — авто-рекомендация под железо"
    echo -e "  ${CYAN}[5]${NC} ${GREEN}wizard${NC} — гид по настройке (5 шагов)"
    echo -e "  ${CYAN}[6]${NC} install — компоненты Phoenix-X"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) apply_optimizations ;;
        2) LEARN_MODE=1; DRY_RUN=1 apply_optimizations; LEARN_MODE=0; DRY_RUN=0; read -r -p "Enter..." ;;
        3) manage_presets_menu ;;
        4) suggest_command; read -r -p "Enter..." ;;
        5) wizard_command; read -r -p "Enter..." ;;
        6) install_dependencies; read -r -p "Enter..." ;;
        0) ;;
    esac
}

_menu_stealth() {
    clear
    echo -e "${MAGENTA}${BOLD}🎭 Stealth${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} noise — генератор шума (iOS + RU + APT)"
    echo -e "  ${CYAN}[2]${NC} stealth-test — JA3 leak self-check"
    echo -e "  ${CYAN}[3]${NC} stealth-test --json --ja4"
    echo -e "  ${CYAN}[4]${NC} DNS plain/DoT/DoH/DoQ/DNSSEC/padding"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) manage_noise_generator ;;
        2) stealth_test_command; read -r -p "Enter..." ;;
        3) stealth_test_command --json --ja4; read -r -p "Enter..." ;;
        4) manage_dns_menu ;;
        0) ;;
    esac
}

_menu_diagnostics() {
    clear
    echo -e "${CYAN}${BOLD}🩺 Diagnostics${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} doctor — проверка состояния"
    echo -e "  ${CYAN}[2]${NC} status — текущее состояние"
    echo -e "  ${CYAN}[3]${NC} status --watch (live, Ctrl-C выход)"
    echo -e "  ${CYAN}[4]${NC} top — топ TCP retransmits"
    echo -e "  ${CYAN}[5]${NC} ${GREEN}log-tail${NC} — цветной tail логов"
    echo -e "  ${CYAN}[6]${NC} mtr <host>"
    echo -e "  ${CYAN}[7]${NC} audit — последние применённые изменения"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) doctor_command; read -r -p "Enter..." ;;
        2) print_status_dashboard; read -r -p "Enter..." ;;
        3) trap 'echo; return 0' INT; while true; do clear; echo -e "${GRAY}status --watch (Ctrl-C выход)${NC}"; print_status_dashboard; sleep 2; done ;;
        4) top_command; read -r -p "Enter..." ;;
        5) log_tail_command ;;
        6) read -r -p "host: " h; [ -n "$h" ] && mtr_command "$h"; read -r -p "Enter..." ;;
        7) audit_command; read -r -p "Enter..." ;;
        0) ;;
    esac
}

_menu_config() {
    clear
    echo -e "${CYAN}${BOLD}⚙  Config${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} swap — настройки swap/zram"
    echo -e "  ${CYAN}[2]${NC} preset (balanced / proxy / web)"
    echo -e "  ${CYAN}[3]${NC} язык интерфейса (en/ru/de/fr/zh)"
    echo -e "  ${CYAN}[4]${NC} ${GREEN}profile${NC} save/load/list — снапшоты конфигурации"
    echo -e "  ${CYAN}[5]${NC} ${GREEN}install-completion${NC} — bash + zsh tab-completion"
    echo -e "  ${CYAN}[6]${NC} harden ssh/ufw/upgrades/all (opt-in)"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) manage_swap ;;
        2) manage_presets_menu ;;
        3)
            read -r -p "Язык (en/ru/de/fr/zh): " lng
            case "$lng" in
                en|ru|de|fr|zh) config_command lang "$lng"; read -r -p "Enter..." ;;
                *) echo -e "${YELLOW}неизвестный язык${NC}"; sleep 1 ;;
            esac
            ;;
        4)
            profile_command list
            echo ""
            echo "  [s] save / [l] load / [d] delete / Enter — назад"
            read -r -p "> " pa
            case "$pa" in
                s) read -r -p "Имя профиля: " nm; [ -n "$nm" ] && profile_command save "$nm"; read -r -p "Enter..." ;;
                l) read -r -p "Имя профиля: " nm; [ -n "$nm" ] && profile_command load "$nm"; read -r -p "Enter..." ;;
                d) read -r -p "Имя профиля: " nm; [ -n "$nm" ] && profile_command delete "$nm"; read -r -p "Enter..." ;;
            esac
            ;;
        5) install_completion_command; read -r -p "Enter..." ;;
        6)
            echo "  [1] all  [2] ssh  [3] ufw  [4] upgrades"
            read -r -p "Выбор: " hs
            case "$hs" in
                1) harden_command all; read -r -p "Enter..." ;;
                2) harden_command ssh; read -r -p "Enter..." ;;
                3) harden_command ufw; read -r -p "Enter..." ;;
                4) harden_command upgrades; read -r -p "Enter..." ;;
            esac
            ;;
        0) ;;
    esac
}

_menu_monitoring() {
    clear
    echo -e "${YELLOW}${BOLD}📊 Monitoring${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} benchmark — пинг до популярных endpoints"
    echo -e "  ${CYAN}[2]${NC} ${GREEN}bench-suite${NC} — iperf3 baseline до 4 серверов + CSV"
    echo -e "  ${CYAN}[3]${NC} prom-metrics — Prometheus output на stdout"
    echo -e "  ${CYAN}[4]${NC} prom-serve [port=9777] — поднять Prometheus exporter"
    echo -e "  ${CYAN}[5]${NC} health-watch on/off (фоновый daemon)"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) run_benchmark; read -r -p "Enter..." ;;
        2) bench_suite_command; read -r -p "Enter..." ;;
        3) prom_metrics; read -r -p "Enter..." ;;
        4) read -r -p "Порт [9777]: " pp; prom_serve "${pp:-9777}" ;;
        5) read -r -p "on/off/status [status]: " hw; health_watch_command "${hw:-status}"; read -r -p "Enter..." ;;
        0) ;;
    esac
}

_menu_misc() {
    clear
    echo -e "${CYAN}${BOLD}📦 Misc${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} install — зависимости Phoenix-X"
    echo -e "  ${CYAN}[2]${NC} export — конфиги в /tmp/vps-phoenix-bundle.tar.gz"
    echo -e "  ${CYAN}[3]${NC} import — из tar.gz"
    echo -e "  ${CYAN}[4]${NC} update — self-update из GitHub"
    echo -e "  ${CYAN}[5]${NC} backup-config <rclone-remote>"
    echo -e "  ${CYAN}[0]${NC} Назад"
    echo ""
    read -r -p "Выбор: " p
    case "$p" in
        1) install_dependencies; read -r -p "Enter..." ;;
        2) export_config; read -r -p "Enter..." ;;
        3) read -r -p "Путь к архиву: " ap; [ -n "$ap" ] && import_config "$ap"; read -r -p "Enter..." ;;
        4) self_update; read -r -p "Enter..." ;;
        5) read -r -p "rclone remote (например s3:mybucket/vps): " rc; [ -n "$rc" ] && backup_config_command "$rc"; read -r -p "Enter..." ;;
        0) ;;
    esac
}

# ===================================================================
#  Точка входа: CLI или интерактивное меню
# ===================================================================

if [ $# -gt 0 ]; then
    CLI_MODE=1
    # help/status/version/prom-metrics — без проверки root, остальные команды требуют sudo
    case "$1" in
        help|-h|--help) print_cli_help; exit 0 ;;
        version|--version|-V) echo "vps_optimizer.sh v$SCRIPT_VERSION"; exit 0 ;;
        config)
            # v8.6: config show — без root; config lang — требует root для записи
            shift
            if [ "${1:-show}" = "show" ] || [ -z "${1:-}" ]; then
                config_command show
                exit 0
            fi
            check_root
            config_command "$@"
            exit $?
            ;;
        status)
            shift
            # Поддержка --json и --watch без root
            for a in "$@"; do
                [ "$a" = "--json" ] && { status_json; exit 0; }
            done
            for a in "$@"; do
                if [ "$a" = "--watch" ]; then
                    # v8.6: status --watch — live update каждые 2с до Ctrl-C.
                    # Тише header, бесконечный цикл, корректный exit на Ctrl-C.
                    trap 'echo; exit 0' INT TERM
                    while true; do
                        clear
                        echo -e "${GRAY}vps-optimizer status --watch (Ctrl-C to exit, refresh=2s)${NC}"
                        echo ""
                        print_status_dashboard
                        sleep 2
                    done
                fi
            done
            print_status_dashboard
            exit 0
            ;;
        prom-metrics) prom_metrics; exit 0 ;;
        _prom_handler) _prom_handler; exit 0 ;;
    esac
    check_root
    cli_dispatch "$@"
    exit $?
fi
check_root
main_menu
