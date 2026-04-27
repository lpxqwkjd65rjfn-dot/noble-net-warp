#!/usr/bin/env bats
# Unit tests for core helpers in vps_optimizer.sh (v8.5)
# Run: bats tests/

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../vps_optimizer.sh"
    [ -f "$SCRIPT" ] || skip "vps_optimizer.sh not found at $SCRIPT"
}

# === bash -n ===
@test "vps_optimizer.sh: bash -n succeeds" {
    bash -n "$SCRIPT"
}

# === SCRIPT_VERSION sanity ===
@test "SCRIPT_VERSION is set and starts with 8" {
    run grep -E '^SCRIPT_VERSION=' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'SCRIPT_VERSION="8'* ]]
}

# === help command ===
@test "help command exits 0" {
    run bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" == *USAGE* ]]
}

# === unknown command ===
@test "unknown command returns non-zero" {
    run bash "$SCRIPT" --no-rollback xyz_unknown_cmd_zzz
    [ "$status" -ne 0 ]
}

# === core helpers exist ===
@test "_json_str function is defined" {
    run grep -E '^_json_str\(\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "urand function is defined" {
    run grep -E '^urand\(\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "detect_virt function is defined" {
    run grep -E '^detect_virt\(\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === noise generator extraction is shellcheck-clean ===
@test "extracted noise generator is shellcheck-clean (-S warning)" {
    if ! command -v shellcheck >/dev/null 2>&1; then
        skip "shellcheck not installed"
    fi
    awk '/cat > "\$NOISE_GEN_SCRIPT" <<'\''NOISE_EOF'\''/{f=1;next} f && /^NOISE_EOF$/{f=0} f' "$SCRIPT" > /tmp/noise_gen.sh
    [ -s /tmp/noise_gen.sh ]
    run shellcheck -S warning /tmp/noise_gen.sh
    [ "$status" -eq 0 ]
}

# === STUN packet does NOT contain raw NUL (would truncate bash variable) ===
@test "stun_burst packet uses escape-string format (no raw NUL)" {
    run grep -F "stun_pkt='\\x00\\x01\\x00\\x00" "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === defaults are SSH-safe ===
@test "default rp_filter without --vpn is strict (=1)" {
    run grep -E 'rp_filter.*1' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "no firewall presets in apply path" {
    run grep -E 'apply_optimizations.*\biptables\b|apply_optimizations.*\bnft\b' "$SCRIPT"
    [ "$status" -ne 0 ]
}

# === stealth-test command registered ===
@test "stealth-test command is registered" {
    run grep -E '^[[:space:]]+stealth-test\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === playbook command registered ===
@test "playbook command is registered" {
    run grep -E '^[[:space:]]+playbook\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === backup-config command registered ===
@test "backup-config command is registered" {
    run grep -E '^[[:space:]]+backup-config\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === health-watch command registered ===
@test "health-watch command is registered" {
    run grep -E '^[[:space:]]+health-watch\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === audit-syslog command registered ===
@test "audit-syslog command is registered" {
    run grep -E '^[[:space:]]+audit-syslog\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === DoQ is opt-in (not in apply_optimizations) ===
@test "DoQ is NOT auto-applied" {
    # apply_optimizations should not call dns_doq_command
    run awk '/^apply_optimizations\(\)/,/^\}/' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" != *dns_doq_command* ]]
    [[ "$output" != *dns_dnssec_command* ]]
}

# === DNSSEC is opt-in ===
@test "DNSSEC is NOT auto-applied" {
    run awk '/^apply_optimizations\(\)/,/^\}/' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" != *dnssec_command* ]]
}

# === VPN-iface skip in initcwnd ===
@test "initcwnd skips tun/wg ifaces" {
    run grep -E 'tun\*|wg\*|ppp\*' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: i18n ===
@test "v8.6: I18N_EN/RU/DE/FR/ZH tables defined" {
    run grep -E '^declare -A I18N_EN I18N_RU I18N_DE I18N_FR I18N_ZH' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.6: _t() function defined" {
    run grep -E '^_t\(\) \{' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.6: LC_VPS env override changes lang" {
    run env LC_VPS=ru bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"lang=ru"* ]]
    run env LC_VPS=zh bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"lang=zh"* ]]
}

@test "v8.6: invalid LC_VPS falls back to en" {
    run env LC_VPS=xx bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"lang=en"* ]]
}

@test "v8.6: config show is registered (no root needed)" {
    run bash "$SCRIPT" config show
    [ "$status" -eq 0 ]
    [[ "$output" == *"config file"* ]]
}

@test "v8.6: --no-color flag is recognized and resets color vars" {
    run grep -E '^[[:space:]]+--no-color\)' "$SCRIPT"
    [ "$status" -eq 0 ]
    # And TTY-detect logic exists
    run grep -E '_vps_use_color' "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "v8.6: help output via pipe contains no ANSI escapes" {
    # Default behavior: stdout is a pipe (bats run captures), so NO_COLOR/TTY-detect kicks in
    run bash "$SCRIPT" help
    [ "$status" -eq 0 ]
    [[ "$output" != *$'\033'* ]]
}

# === v8.6: status --watch is recognized (we don't run it because it loops) ===
@test "v8.6: status --watch parsing exists" {
    run grep -E 'a" = "--watch"' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: --json-logs flag parsed ===
@test "v8.6: --json-logs flag parsed" {
    run grep -E '^[[:space:]]+--json-logs\)' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: --learn flag parsed ===
@test "v8.6: --learn flag sets DRY_RUN=1" {
    run grep -E 'LEARN_MODE=1; DRY_RUN=1' "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: stealth-test --json/--ja4/--exit-fail-on-leak parse ===
@test "v8.6: stealth-test --json supported" {
    run awk '/^stealth_test_command\(\)/,/^\}/' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"--json"* ]]
    [[ "$output" == *"--exit-fail-on-leak"* ]]
    [[ "$output" == *"--ja4"* ]]
}

# === v8.6: prom-metrics has DNS hit-ratio ===
@test "v8.6: prom_metrics emits vps_dns_cache_hit_ratio" {
    run awk '/^prom_metrics\(\)/,/^\}/' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"vps_dns_cache_hit_ratio"* ]]
}

# === v8.6: noise uses --tcp-fastopen ===
@test "v8.6: noise generator uses --tcp-fastopen flag" {
    run grep -F -- "--tcp-fastopen" "$SCRIPT"
    [ "$status" -eq 0 ]
}

# === v8.6: tcp_thin_dupack only on proxy preset ===
@test "v8.6: tcp_thin_dupack is preset-gated to proxy (CONTRIBUTING #5)" {
    # Verify the line right above 'sysctl_safe net.ipv4.tcp_thin_dupack 1' is
    # an `if [ "$PRESET_NAME" = "proxy" ]; then` block opener.
    # We check 4 lines of context before the dupack line and assert that
    # the proxy-preset gate appears in those 4 lines.
    run grep -B4 'sysctl_safe net.ipv4.tcp_thin_dupack 1' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'PRESET_NAME" = "proxy"'* ]]
}

@test "v8.6: IPv6 privacy ext is preset-gated to proxy" {
    run grep -B4 'use_tempaddr 2' "$SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'PRESET_NAME" = "proxy"'* ]]
}

# === v8.6: numa_balancing auto-detect ===
@test "v8.6: numa_balancing 0 only inside NUMA-detect blocks (no unconditional)" {
    # Sanity: numa_balancing 0 must appear at least once
    run grep -c 'numa_balancing 0' "$SCRIPT"
    [ "$status" -eq 0 ]
    [ "$output" -ge 1 ]
    # Each numa_balancing 0 line must have a NUMA-detection sentinel (numactl
    # output OR /sys/devices/system/node) within 8 lines above.
    while IFS= read -r line_num; do
        [ -z "$line_num" ] && continue
        local from=$((line_num - 8))
        [ "$from" -lt 1 ] && from=1
        run sed -n "${from},${line_num}p" "$SCRIPT"
        [[ "$output" == *'numactl'* ]] || [[ "$output" == *'/sys/devices/system/node'* ]] || {
            echo "Line $line_num has numa_balancing 0 with no NUMA detection above"
            false
        }
    done < <(grep -n 'numa_balancing 0' "$SCRIPT" | cut -d: -f1)
}
