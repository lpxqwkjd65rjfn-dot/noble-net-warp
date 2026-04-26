# Contributing

Thanks for taking the time to contribute! This project is a single-file Bash 5+
script — small, focused PRs are easiest to review.

## Ground rules

1. **Keep it Bash 5+**. No language rewrites in this repo.
2. **`bash -n vps_optimizer.sh`** must pass.
3. **`shellcheck -S warning vps_optimizer.sh`** must be clean. Justify any
   `# shellcheck disable=...` you add inline.
4. **Probe-then-write**: every new sysctl/sysfs MUST go through `sysctl_safe`
   or `sysfs_safe`. Never write directly into `/etc/sysctl.d/` without first
   probing the kernel.
5. **Backward compatibility**: do not change the default behaviour of `apply`
   without an opt-in flag. If a knob is potentially destructive on some
   hypervisor / kernel, hide it behind a flag (`--ecmp`, `--impersonate`,
   `harden`, ...).
6. **Idempotency**: `apply` twice should not change state if nothing
   substantive changed. Snapshot+rewrite only when the sysctl content
   actually differs.
7. **No new mandatory dependencies**. If something extra is useful (`socat`,
   `dmidecode`, `curl-impersonate`), gate it: detect at runtime, fall back
   gracefully, install only on opt-in or in `install`.
8. **Audit log it**. Any new mutating command should call `_audit <action> ...`.
9. **Commit messages**: imperative, prefix with the area —
   `noise:`, `dns:`, `apply:`, `cli:`, `docs:`, etc.

## Testing locally

```bash
bash -n vps_optimizer.sh
shellcheck -S warning vps_optimizer.sh
sudo ./vps_optimizer.sh apply --dry-run --debug
sudo ./vps_optimizer.sh status --json | jq .
sudo ./vps_optimizer.sh self-test
```

To validate the embedded noise generator:

```bash
awk '/cat > "\$NOISE_GEN_SCRIPT" <<'\''NOISE_EOF'\''/{f=1;next} f && /^NOISE_EOF$/{f=0} f' \
    vps_optimizer.sh > /tmp/noise_gen.sh
bash -n /tmp/noise_gen.sh
shellcheck -S warning /tmp/noise_gen.sh
```

## PR checklist

- [ ] `bash -n` passes
- [ ] `shellcheck -S warning` is clean (or disables are justified)
- [ ] New mutating commands have an `_audit ...` call
- [ ] New sysctl uses `sysctl_safe`
- [ ] README updated if the CLI surface changed
- [ ] Changelog entry in README under the current version

## Reporting bugs

Include:

- exact command run
- output of `vps_optimizer.sh status --json`
- output of `vps_optimizer.sh audit`
- last 100 lines of `vps_optimizer.sh logs`
- `uname -a` and `lsb_release -d`
- hypervisor (`systemd-detect-virt`) and provider, if known
