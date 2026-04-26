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
