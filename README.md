# Sternwatch

> *Keep a lookout over your stern.* The stern is the tail end of a ship, and Sternwatch keeps watch over your **Tail**scale nodes.

Sternwatch is a **read-only** Bash checker that tells you whether a Tailscale node is exposed to the **"Tailworm"** Tailscale SSH disclosure (25 October 2026) and to the earlier 2026 Tailscale security bulletins. For every risky setting it finds, it gives you the exact command to fix it.

It **never changes anything** on the host it checks.

---

## Why

On 25 October 2026, a researcher published **Tailworm**: 11 unpatched issues in Tailscale and headscale. The headline issue is that **Tailscale SSH** performs Unix-socket port forwarding inside the root `tailscaled` process. An attacker who already controls *one* device in your tailnet, and is allowed by your ACLs to SSH to another, can abuse that forwarding to reach root-owned sockets (Docker, systemd, Tailscale's local API) and escalate to **root on the target**. The attack can then repeat from node to node.

At the time of writing there was **no CVE, bulletin or fixed release**. Exposure therefore depends entirely on **how each node is configured**, and Sternwatch checks exactly that.

> This is post-compromise lateral movement *inside* a tailnet. It is **not** unauthenticated remote code execution from the internet.

---

## What it checks

| ID | Check | Why it matters |
|---|---|---|
| SW-01 | Tailscale version ≥ **1.98.9** | Fixes TS-2026-004 (SSH socket-forwarding symlink bypass), -006 (SSH `autogroup:nonroot`), -007 (Services/loopback) and -008 (Serve/Funnel) |
| SW-02 | Tailworm fixed version | Flags HIGH once you supply `--fixed-version` after Tailscale releases a patch |
| SW-10 | **Tailscale SSH server enabled** (`RunSSH`) | The core Tailworm escalation requires it. Also notes Docker/Podman sockets that the published chain abused |
| SW-20 | Auto-update enabled | So the fix lands as soon as it ships |
| SW-30 | **Tailnet Lock** | The "add a rogue node" step only worked end to end without it |
| SW-31 | Subnet router routes | A compromised peer can reach your whole LAN through this node |
| SW-32 | Exit node | Informational. Make sure exit-node use is limited in ACLs |
| SW-33 | App Connector | Flagged by the Tailworm report as potentially even more impactful |
| SW-34 | Serve / Funnel | Affected by TS-2026-008. Funnel exposes services to the internet |
| SW-40 | headscale installed | Tailworm reports headscale grants SSH forwarding unconditionally |
| SW-41 | Custom control server | Probably headscale, so per-rule forwarding limits don't apply |
| SW-50 | Shields Up | Informational. The node refuses all inbound tailnet connections |

Severities: **HIGH** · **MEDIUM** · **LOW** · **INFO** · **PASS**

---

## Quick start

```bash
git clone https://github.com/Mr-Whiskerss/sternwatch.git
cd sternwatch
chmod +x sternwatch.sh

sudo ./sternwatch.sh
```

`sudo` is recommended so Sternwatch can read `tailscaled`'s preferences. It only *reads*.

### Example output

```
⚓ Sternwatch v1.0.0 — ubuntu-tailscale — 2026-10-26 16:44
Read-only. Nothing on this machine will be changed.

▸ Tailscale SSH (Tailworm core issue)
  [HIGH  ] Tailscale SSH server is ENABLED on this node
           ↳ If you don't need it: 'sudo tailscale set --ssh=false' ...

▸ Tailnet hardening
  [MEDIUM] Tailnet Lock is not enabled
  [MEDIUM] Node is a subnet router for: 192.168.1.0/24

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary  HIGH 1  MEDIUM 2  LOW 0  INFO 2  PASS 4
```

---

## Usage

```
sternwatch.sh [options]                     check this machine
sternwatch.sh --hosts host1,user@host2      check remote hosts over SSH
sternwatch.sh --hosts @hosts.txt            one host per line (# comments ok)

  --json FILE            all findings as one JSON document
  --jsonl FILE           JSON Lines, one finding per line (for pipelines / SIEM)
  --html FILE            dark-themed HTML report
  --fixed-version X.Y.Z  the Tailscale version that fixes Tailworm, once released
  --timeout N            per-command timeout in seconds (default 10)
  --ssh-timeout N        per-host timeout in --hosts mode (default 60)
  --no-color             plain output
  -q, --quiet            only print the summary
  -V, --version / -h, --help
```

### Check your whole fleet

```bash
cat > hosts.txt <<'EOF'
# tailnet nodes
root@192.168.1.0     # exit node
test@tailscale1
EOF

./sternwatch.sh --hosts @hosts.txt --html report.html --jsonl findings.jsonl
```

The script copies itself to each host over SSH (`bash -s`), runs read-only there, and returns JSONL. Nothing is installed on the remote host. You get a per-host summary table at the end:

```
HOST                          HIGH MEDIUM  LOW  PASS
root@192.168.1.1               0      1    0     5
                               1      2    0     3
```

SSH uses `BatchMode=yes`, so key-based authentication is required, and each host has a hard timeout.

### Once Tailscale ships the fix

```bash
./sternwatch.sh --fixed-version 1.104.X
```

Any node below that version is then flagged **HIGH**.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No HIGH or MEDIUM findings |
| `1` | MEDIUM findings present |
| `2` | HIGH findings present |
| `3` | Error (Tailscale missing or daemon unreachable) |

These make it easy to run from cron or CI and alert on a non-zero exit.

---

## Fixing what it finds

| Finding | Fix |
|---|---|
| Tailscale SSH enabled | `sudo tailscale set --ssh=false`, and use normal OpenSSH over the tailnet |
| Still need Tailscale SSH | ACL SSH rules: specific `src`/`dst`, `"action": "check"`, no `root`, no forwarding |
| Auto-update off | `sudo tailscale set --auto-update` |
| Tailnet Lock off | Admin console → Settings → Device management → **Tailnet Lock** |
| Subnet router | Restrict grants for the subnet to specific users/devices and ports, not `*` |
| App Connector | `sudo tailscale set --advertise-connector=false` |
| Funnel / Serve | `tailscale funnel reset` / `tailscale serve reset` |
| Old version | `sudo tailscale update` |

Some things live only in the **admin console** and can't be seen from a node: ACL/grant rules, SSH rules, unused devices and key expiry. Review those by hand.

---

## Design notes

- **Read-only by default.** No flag makes it change settings.
- **Hard timeouts** on every external call (`timeout`, `gtimeout`, or a `perl` alarm fallback).
- **Bash 3.2 compatible**, so it runs on macOS out of the box.
- **JSON / JSONL / HTML** output for pipelines and reports.
- `python3` is used for exact JSON parsing if present; otherwise a `sed` fallback handles the known preference layout.
- Supported: Linux (systemd or not) and macOS (CLI or App Store app). Windows nodes aren't covered; check those in the admin console.

---

## References

- Tailworm report: <https://tailworm.com/>
- The Hacker News, *Unpatched Tailscale SSH Flaws Could Let a Hacked Device Reach Root on Other Servers* (25 Oct 2026)
- Tailscale security bulletins: <https://tailscale.com/security-bulletins> (RSS: `https://tailscale.com/security-bulletins/index.xml`)
- Tailnet Lock: <https://tailscale.com/kb/1226/tailnet-lock>

---

## Disclaimer

Sternwatch checks **local node configuration** against publicly reported conditions. It does not exploit anything and cannot prove that a node is safe. Tailscale had not confirmed the full technical details of Tailworm when this was written. Keep Tailscale updated and follow the official bulletins.

## License

MIT © Dan ([@Mr-Whiskerss](https://github.com/Mr-Whiskerss))
