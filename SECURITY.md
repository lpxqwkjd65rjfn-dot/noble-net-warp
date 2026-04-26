# Security policy

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Open a private GitHub Security Advisory:
<https://github.com/lpxqwkjd65rjfn-dot/noble-net-warp/security/advisories/new>

Include:

- a clear description of the issue and impact
- step-by-step reproduction
- affected version (e.g. `v8.2`)
- ideally, a suggested fix or mitigation

We will acknowledge within 7 days and aim to ship a fix in the next release.

## Scope

In scope:

- code execution, privilege escalation, or local DoS via `vps_optimizer.sh`
- broken / persisted dangerous sysctl that survives `reset`
- the embedded `vps_noise_gen.sh` exfiltrating content (it MUST always use
  `curl -o /dev/null`)
- self-update path (`update` command) — MITM, missing checksum verification,
  failure to roll back a broken script

Out of scope:

- hardening recommendations for unrelated services on the host
- third-party tools we install (dnscrypt-proxy, dnsmasq, curl-impersonate)
  — please report those upstream
- DoS via legitimate `apply` of an inappropriate preset on a tiny host

## Hardening already in place

- Probe-then-write for every sysctl/sysfs.
- `vps-noise.service`: `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome`,
  `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`,
  `LockPersonality`, `RestrictSUIDSGID`, `RestrictNamespaces`,
  `NoNewPrivileges`, `MemoryMax=256M`, `TasksMax=64`, `Restart=on-failure`,
  `StartLimitBurst=5`.
- Lock file (`/var/lock/vps-optimizer.lock`) prevents racing `apply`s.
- Pre-apply snapshot in `/var/backups/vps-optimizer/` enables rollback.
- Audit log in `/var/log/vps-optimizer-audit.log` for every mutating command.
- `self-update` verifies SHA256 (sidecar `.sha256`) when present and rolls
  back if `--help` fails on the new script.
- `harden` is opt-in; default `apply` does not change SSH or firewall.
