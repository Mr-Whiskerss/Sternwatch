#!/usr/bin/env bash
# =============================================================================
#  Sternwatch — keep a lookout over your Tailscale node's stern
#
#  Read-only exposure checker for the "Tailworm" Tailscale SSH disclosure
#  (published 25 Oct 2026) and earlier 2026 Tailscale security bulletins.
#
#  Sternwatch NEVER changes anything. It reads local Tailscale state and
#  reports what an attacker with a foothold on one tailnet device could use.
#
#  Author : Dan (github.com/Mr-Whiskerss)
#  License: MIT
# =============================================================================
#  Bash 3.2 compatible (macOS) — no associative arrays, no ${var,,}, no mapfile.
# =============================================================================

set -u

VERSION="1.0.0"
PROG="sternwatch"

# Last Tailscale release that fixed the 2026 bulletins TS-2026-004/006/007/008.
MIN_SAFE_VERSION="1.98.9"
# Tailworm had no fixed release at time of writing. Set with --fixed-version
# once Tailscale publishes one, and Sternwatch will compare against it.
TAILWORM_FIXED_VERSION=""

CMD_TIMEOUT=10          # seconds, hard limit on every external call
SSH_TIMEOUT=60          # seconds, per remote host in --hosts mode
JSONL_OUT=""
JSON_OUT=""
HTML_OUT=""
HOSTS_SPEC=""
QUIET=0
NO_COLOR=0
EMIT_JSONL_STDOUT=0     # internal: used by --hosts remote runs

# ---------------------------------------------------------------- colours ---
setup_colours() {
    if [ "$NO_COLOR" -eq 1 ] || [ ! -t 1 ] || [ "$EMIT_JSONL_STDOUT" -eq 1 ]; then
        C_RST=""; C_BLD=""; C_DIM=""; C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_CYN=""
    else
        C_RST=$'\033[0m'; C_BLD=$'\033[1m'; C_DIM=$'\033[2m'
        C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'
        C_BLU=$'\033[34m'; C_CYN=$'\033[36m'
    fi
}

# ------------------------------------------------------------------ usage ---
usage() {
cat <<EOF
${PROG} v${VERSION} — read-only Tailscale exposure checker (Tailworm & 2026 bulletins)

Usage:
  ${PROG}.sh [options]                     check this machine
  ${PROG}.sh --hosts host1,user@host2      check remote Linux/macOS hosts over SSH
  ${PROG}.sh --hosts @hosts.txt            ... one host per line (# comments ok)

Options:
  --json FILE            write all findings as a JSON document
  --jsonl FILE           write findings as JSON Lines (one finding per line)
  --html FILE            write a dark-themed HTML report
  --fixed-version X.Y.Z  Tailscale version that fixes Tailworm, once released
  --timeout N            per-command timeout in seconds (default ${CMD_TIMEOUT})
  --ssh-timeout N        per-host timeout in --hosts mode (default ${SSH_TIMEOUT})
  --no-color             plain output
  -q, --quiet            only print the summary
  -V, --version          print version
  -h, --help             this help

Exit codes:
  0  no HIGH or MEDIUM findings
  1  MEDIUM findings present
  2  HIGH findings present
  3  error (e.g. Tailscale not installed / not running)

Sternwatch is read-only. It never changes Tailscale settings; every finding
includes the command you would run to fix it yourself.
EOF
}

# --------------------------------------------------------------- argparse ---
while [ $# -gt 0 ]; do
    case "$1" in
        --json)          JSON_OUT="${2:-}"; shift 2 ;;
        --jsonl)         JSONL_OUT="${2:-}"; shift 2 ;;
        --html)          HTML_OUT="${2:-}"; shift 2 ;;
        --hosts)         HOSTS_SPEC="${2:-}"; shift 2 ;;
        --fixed-version) TAILWORM_FIXED_VERSION="${2:-}"; shift 2 ;;
        --timeout)       CMD_TIMEOUT="${2:-10}"; shift 2 ;;
        --ssh-timeout)   SSH_TIMEOUT="${2:-60}"; shift 2 ;;
        --no-color)      NO_COLOR=1; shift ;;
        -q|--quiet)      QUIET=1; shift ;;
        --emit-jsonl)    EMIT_JSONL_STDOUT=1; shift ;;   # internal
        -V|--version)    echo "${PROG} ${VERSION}"; exit 0 ;;
        -h|--help)       setup_colours; usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 3 ;;
    esac
done

setup_colours

# ------------------------------------------------------- timeout wrapper ---
# Portable hard timeout: GNU timeout, then gtimeout (Homebrew), then perl alarm.
TO_BIN=""
if command -v timeout >/dev/null 2>&1; then TO_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TO_BIN="gtimeout"
fi

run_t() {   # run_t SECONDS cmd args...
    local t="$1"; shift
    if [ -n "$TO_BIN" ]; then
        "$TO_BIN" "$t" "$@"
    elif command -v perl >/dev/null 2>&1; then
        perl -e 'alarm shift; exec @ARGV or exit 127' "$t" "$@"
    else
        "$@"
    fi
}

# ---------------------------------------------------------- JSON helpers ---
json_escape() {
    # Escape backslash, double quote, and control characters for JSON strings.
    printf '%s' "$1" | awk '
        BEGIN { ORS="" }
        {
            gsub(/\\/, "\\\\"); gsub(/"/, "\\\"");
            gsub(/\t/, "\\t"); gsub(/\r/, "\\r");
            if (NR > 1) printf "\\n";
            printf "%s", $0
        }'
}

html_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# ------------------------------------------------------- version compare ---
# ver_lt A B  -> true if A < B (numeric dotted compare, ignores suffixes)
ver_lt() {
    local a="$1" b="$2" i ai bi
    a="${a%%-*}"; b="${b%%-*}"
    i=1
    while [ $i -le 4 ]; do
        ai=$(printf '%s' "$a" | cut -d. -f$i); bi=$(printf '%s' "$b" | cut -d. -f$i)
        ai="${ai:-0}"; bi="${bi:-0}"
        case "$ai" in *[!0-9]*|"") ai=0 ;; esac
        case "$bi" in *[!0-9]*|"") bi=0 ;; esac
        if [ "$ai" -lt "$bi" ]; then return 0; fi
        if [ "$ai" -gt "$bi" ]; then return 1; fi
        i=$((i + 1))
    done
    return 1
}

# ------------------------------------------------------ finding storage ---
HOST_LABEL="$(hostname 2>/dev/null || echo unknown)"
FINDINGS_FILE="$(mktemp "${TMPDIR:-/tmp}/${PROG}.XXXXXX")" || exit 3
trap 'rm -f "$FINDINGS_FILE" "${AGG_FILE:-}"' EXIT

CNT_HIGH=0; CNT_MED=0; CNT_LOW=0; CNT_INFO=0; CNT_PASS=0

# add_finding ID SEVERITY TITLE DETAIL RECOMMENDATION REFERENCE
#   SEVERITY: HIGH | MEDIUM | LOW | INFO | PASS
add_finding() {
    local id="$1" sev="$2" title="$3" detail="$4" rec="$5" ref="$6"
    case "$sev" in
        HIGH)   CNT_HIGH=$((CNT_HIGH + 1)) ;;
        MEDIUM) CNT_MED=$((CNT_MED + 1)) ;;
        LOW)    CNT_LOW=$((CNT_LOW + 1)) ;;
        INFO)   CNT_INFO=$((CNT_INFO + 1)) ;;
        PASS)   CNT_PASS=$((CNT_PASS + 1)) ;;
    esac
    printf '{"tool":"%s","version":"%s","host":"%s","id":"%s","severity":"%s","title":"%s","detail":"%s","recommendation":"%s","reference":"%s","timestamp":"%s"}\n' \
        "$PROG" "$VERSION" "$(json_escape "$HOST_LABEL")" "$id" "$sev" \
        "$(json_escape "$title")" "$(json_escape "$detail")" \
        "$(json_escape "$rec")" "$(json_escape "$ref")" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$FINDINGS_FILE"

    [ "$QUIET" -eq 1 ] && return 0
    [ "$EMIT_JSONL_STDOUT" -eq 1 ] && return 0
    local col tag
    case "$sev" in
        HIGH)   col="$C_RED"; tag="HIGH  " ;;
        MEDIUM) col="$C_YEL"; tag="MEDIUM" ;;
        LOW)    col="$C_BLU"; tag="LOW   " ;;
        INFO)   col="$C_CYN"; tag="INFO  " ;;
        PASS)   col="$C_GRN"; tag="PASS  " ;;
    esac
    printf '  %s[%s]%s %s%s%s\n' "$col" "$tag" "$C_RST" "$C_BLD" "$title" "$C_RST"
    [ -n "$detail" ] && printf '           %s%s%s\n' "$C_DIM" "$detail" "$C_RST"
    if [ -n "$rec" ] && [ "$sev" != "PASS" ] && [ "$sev" != "INFO" ]; then
        printf '           %s↳ %s%s\n' "$C_CYN" "$rec" "$C_RST"
    fi
}

section() {
    [ "$QUIET" -eq 1 ] && return 0
    [ "$EMIT_JSONL_STDOUT" -eq 1 ] && return 0
    printf '\n%s%s▸ %s%s\n' "$C_BLD" "$C_BLU" "$1" "$C_RST"
}

# ------------------------------------------------------- pref extraction ---
# `tailscale debug prefs` prints pretty JSON. Use python3 if present for exact
# parsing; otherwise fall back to grep/sed on the known key layout.
PREFS=""
HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1

pref_get() {   # pref_get Dotted.Key  -> prints value (true/false/string/list)
    local key="$1"
    if [ "$HAVE_PY" -eq 1 ]; then
        printf '%s' "$PREFS" | python3 -I -c '
import json, sys
key = sys.argv[1].split(".")
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for k in key:
    if isinstance(d, dict) and k in d:
        d = d[k]
    else:
        sys.exit(0)
if isinstance(d, bool):
    print("true" if d else "false")
elif isinstance(d, list):
    print(",".join(str(x) for x in d))
elif d is None:
    print("")
else:
    print(d)
' "$key" 2>/dev/null
    else
        local leaf="${key##*.}" flat val
        flat="$(printf '%s' "$PREFS" | tr -d '\n')"
        # Arrays first (e.g. AdvertiseRoutes), then scalars.
        val="$(printf '%s' "$flat" | sed -n "s/.*\"$leaf\": *\(\[[^]]*\]\).*/\1/p" | head -1)"
        [ -z "$val" ] && val="$(printf '%s' "$flat" | sed -n "s/.*\"$leaf\": *\([^,}]*\).*/\1/p" | head -1)"
        printf '%s' "$val" | tr -d '" []'
    fi
}

# =============================================================== CHECKS ====
run_checks() {
    if [ "$QUIET" -eq 0 ] && [ "$EMIT_JSONL_STDOUT" -eq 0 ]; then
        printf '%s%s⚓ Sternwatch v%s%s — %s — %s\n' "$C_BLD" "$C_CYN" "$VERSION" "$C_RST" "$HOST_LABEL" "$(date '+%Y-%m-%d %H:%M')"
        printf '%sRead-only. Nothing on this machine will be changed.%s\n' "$C_DIM" "$C_RST"
    fi

    # ---------------------------------------------------- presence & daemon
    section "Tailscale presence"
    local TS
    TS="$(command -v tailscale 2>/dev/null)"
    if [ -z "$TS" ] && [ -x /Applications/Tailscale.app/Contents/MacOS/Tailscale ]; then
        TS="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
    fi
    if [ -z "$TS" ]; then
        add_finding "SW-00" "INFO" "Tailscale not installed" \
            "No tailscale CLI found on this host — nothing to check." "" ""
        return 3
    fi

    local status_out
    if ! status_out="$(run_t "$CMD_TIMEOUT" "$TS" status --peers=false 2>&1)"; then
        case "$status_out" in
            *"Logged out"*|*"NeedsLogin"*)
                add_finding "SW-00" "INFO" "Tailscale installed but logged out" \
                    "tailscaled is running but this node is not joined to a tailnet." "" "" ;;
            *)
                add_finding "SW-00" "INFO" "Tailscale daemon not reachable" \
                    "$(printf '%s' "$status_out" | head -1)" \
                    "Start tailscaled (systemctl start tailscaled) and re-run, or run Sternwatch with sudo." ""
                return 3 ;;
        esac
    fi

    PREFS="$(run_t "$CMD_TIMEOUT" "$TS" debug prefs 2>/dev/null)"
    if [ -z "$PREFS" ]; then
        add_finding "SW-00" "INFO" "Could not read Tailscale prefs" \
            "'tailscale debug prefs' returned nothing (permissions?)." \
            "Re-run Sternwatch with sudo so it can read tailscaled's preferences." ""
    fi

    # ------------------------------------------------------------- version
    section "Version"
    local ver_raw ver
    ver_raw="$(run_t "$CMD_TIMEOUT" "$TS" version 2>/dev/null | head -1)"
    ver="$(printf '%s' "$ver_raw" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [ -z "$ver" ]; then
        add_finding "SW-01" "MEDIUM" "Tailscale version could not be determined" \
            "Raw output: ${ver_raw:-<none>}" "Run 'tailscale version' manually." ""
    elif ver_lt "$ver" "$MIN_SAFE_VERSION"; then
        add_finding "SW-01" "HIGH" "Tailscale ${ver} is missing 2026 security fixes" \
            "Versions before ${MIN_SAFE_VERSION} are affected by TS-2026-004 (Tailscale SSH socket-forwarding symlink bypass), TS-2026-006 (SSH autogroup:nonroot), TS-2026-007 (Services/loopback) and TS-2026-008 (Serve/Funnel)." \
            "Update Tailscale now (Linux: 'sudo tailscale update' or your package manager) and enable auto-updates." \
            "https://tailscale.com/security-bulletins"
    else
        add_finding "SW-01" "PASS" "Tailscale ${ver} includes the fixes up to ${MIN_SAFE_VERSION}" "" "" ""
    fi

    if [ -n "$ver" ]; then
        if [ -n "$TAILWORM_FIXED_VERSION" ]; then
            if ver_lt "$ver" "$TAILWORM_FIXED_VERSION"; then
                add_finding "SW-02" "HIGH" "Tailscale ${ver} predates the Tailworm fix (${TAILWORM_FIXED_VERSION})" \
                    "The Tailworm Tailscale SSH forwarding issues are fixed in ${TAILWORM_FIXED_VERSION}." \
                    "Update Tailscale to ${TAILWORM_FIXED_VERSION} or newer." \
                    "https://tailscale.com/security-bulletins"
            else
                add_finding "SW-02" "PASS" "Tailscale ${ver} includes the Tailworm fix (${TAILWORM_FIXED_VERSION})" "" "" ""
            fi
        else
            add_finding "SW-02" "INFO" "No fixed Tailscale release for Tailworm is known to this version of Sternwatch" \
                "Tailworm (25 Oct 2026) was disclosed against Tailscale 1.104.2 with no patch available. Exposure depends on the configuration checks below. Re-run with --fixed-version X.Y.Z once Tailscale publishes a fix." \
                "Watch https://tailscale.com/security-bulletins/index.xml" \
                "https://tailworm.com/"
        fi
    fi

    # ------------------------------------------------------ Tailscale SSH
    section "Tailscale SSH (Tailworm core issue)"
    local run_ssh docker_sock="" sock
    run_ssh="$(pref_get RunSSH)"
    for sock in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock; do
        [ -S "$sock" ] && docker_sock="$sock" && break
    done
    if [ "$run_ssh" = "true" ]; then
        local extra=""
        [ -n "$docker_sock" ] && extra=" A container runtime socket is present (${docker_sock}) — the published chain abused root-owned sockets like this one."
        add_finding "SW-10" "HIGH" "Tailscale SSH server is ENABLED on this node" \
            "Tailworm lets an attacker who controls another tailnet device that is allowed to SSH here use Unix-socket forwarding (performed by root tailscaled) to reach root-owned sockets and escalate to root.${extra}" \
            "If you don't need it: 'sudo tailscale set --ssh=false' (use OpenSSH over the tailnet instead). If you do: restrict SSH ACL rules to specific src/dst, use action \"check\", avoid root, and disable forwarding in the policy." \
            "https://thehackernews.com/2026/10/unpatched-tailscale-ssh-flaws-could-let.html"
    elif [ "$run_ssh" = "false" ]; then
        add_finding "SW-10" "PASS" "Tailscale SSH server is disabled" \
            "The core Tailworm privilege escalation requires Tailscale SSH on the target node." "" ""
    else
        add_finding "SW-10" "MEDIUM" "Could not determine whether Tailscale SSH is enabled" \
            "RunSSH not found in prefs." "Check with: tailscale debug prefs | grep -i RunSSH" ""
    fi

    # ---------------------------------------------------------- auto-update
    section "Patching"
    local au
    au="$(pref_get AutoUpdate.Apply)"
    case "$(uname -s 2>/dev/null)" in
        Darwin)
            add_finding "SW-20" "INFO" "macOS: updates come from the App Store / Tailscale app" \
                "Confirm automatic updates are on in the Tailscale menu-bar app or App Store." "" "" ;;
        *)
            if [ "$au" = "true" ]; then
                add_finding "SW-20" "PASS" "Tailscale auto-update is enabled" \
                    "The Tailworm fix will install automatically when released." "" ""
            else
                add_finding "SW-20" "MEDIUM" "Tailscale auto-update is NOT enabled" \
                    "With an unpatched public disclosure, the fix should land the moment it ships." \
                    "sudo tailscale set --auto-update" \
                    "https://tailscale.com/kb/1067/update"
            fi ;;
    esac

    # ---------------------------------------------------------- tailnet lock
    section "Tailnet hardening"
    local lock_out
    lock_out="$(run_t "$CMD_TIMEOUT" "$TS" lock status 2>&1)"
    case "$lock_out" in
        *"is ENABLED"*|*"is enabled"*)
            add_finding "SW-30" "PASS" "Tailnet Lock is enabled" \
                "New nodes must be signed by a trusted key — blocks the rogue-node step of the Tailworm chain." "" "" ;;
        *"NOT enabled"*|*"not enabled"*|*"is disabled"*)
            add_finding "SW-30" "MEDIUM" "Tailnet Lock is not enabled" \
                "The Tailworm report's 'add a rogue node' step only worked end to end on tailnets without Tailnet Lock." \
                "Admin console → Settings → Device management → Tailnet Lock (or 'tailscale lock init')." \
                "https://tailscale.com/kb/1226/tailnet-lock" ;;
        *)
            add_finding "SW-30" "INFO" "Tailnet Lock status unknown" \
                "$(printf '%s' "$lock_out" | head -1)" "" "" ;;
    esac

    # ------------------------------------------------- subnet / exit node
    local routes route_list="" has_exit=0 r
    routes="$(pref_get AdvertiseRoutes)"
    if [ -n "$routes" ]; then
        local IFS_OLD="$IFS"; IFS=','
        for r in $routes; do
            case "$r" in
                0.0.0.0/0|::/0) has_exit=1 ;;
                "") ;;
                *) route_list="${route_list:+$route_list, }$r" ;;
            esac
        done
        IFS="$IFS_OLD"
    fi
    if [ -n "$route_list" ]; then
        add_finding "SW-31" "MEDIUM" "Node is a subnet router for: ${route_list}" \
            "Any compromised tailnet device permitted by ACLs can reach these LAN ranges through this node — a much larger blast radius for lateral movement." \
            "Restrict ACL/grant rules for these subnets to specific users/devices and ports instead of '*'." \
            "https://tailscale.com/kb/1019/subnets"
    fi
    if [ "$has_exit" -eq 1 ]; then
        add_finding "SW-32" "INFO" "Node advertises itself as an exit node" \
            "Expected for an exit node. Make sure exit-node use (autogroup:internet) is limited to your own devices in ACLs." "" \
            "https://tailscale.com/kb/1103/exit-nodes"
    fi
    if [ -z "$route_list" ] && [ "$has_exit" -eq 0 ]; then
        add_finding "SW-31" "PASS" "Node does not advertise subnet routes or an exit node" "" "" ""
    fi

    # ------------------------------------------------------ app connector
    local appc
    appc="$(pref_get AppConnector.Advertise)"
    if [ "$appc" = "true" ]; then
        add_finding "SW-33" "MEDIUM" "Node is advertised as an App Connector" \
            "The Tailworm report flags App Connectors (conn25) as potentially more impactful than the SSH issue for some organisations." \
            "If not required: 'sudo tailscale set --advertise-connector=false'." \
            "https://tailworm.com/"
    else
        add_finding "SW-33" "PASS" "Node is not an App Connector" "" "" ""
    fi

    # -------------------------------------------------------- serve/funnel
    local serve_out funnel_on=0 serve_on=0
    serve_out="$(run_t "$CMD_TIMEOUT" "$TS" serve status 2>&1)"
    case "$serve_out" in
        *"No serve config"*|*"no serve config"*|"") ;;
        *"Funnel on"*|*"funnel on"*) funnel_on=1; serve_on=1 ;;
        *"http"*|*"tcp"*) serve_on=1 ;;
    esac
    if [ "$funnel_on" -eq 1 ]; then
        add_finding "SW-34" "MEDIUM" "Tailscale Funnel is exposing a service to the public internet" \
            "Funnel/Serve were affected by TS-2026-008 (fixed in ${MIN_SAFE_VERSION}) and are mentioned in the Tailworm audit." \
            "Review with 'tailscale funnel status'; turn off what you don't need ('tailscale funnel reset')." \
            "https://tailscale.com/security-bulletins"
    elif [ "$serve_on" -eq 1 ]; then
        add_finding "SW-34" "LOW" "Tailscale Serve is publishing services to the tailnet" \
            "Serve was affected by TS-2026-008 (fixed in ${MIN_SAFE_VERSION})." \
            "Review with 'tailscale serve status'; 'tailscale serve reset' to remove." \
            "https://tailscale.com/security-bulletins"
    else
        add_finding "SW-34" "PASS" "No Tailscale Serve/Funnel configuration" "" "" ""
    fi

    # ---------------------------------------------------- control server
    local ctrl
    ctrl="$(pref_get ControlURL)"
    if command -v headscale >/dev/null 2>&1; then
        add_finding "SW-40" "HIGH" "headscale is installed on this host" \
            "Tailworm reports headscale 0.29.5 grants SSH forwarding unconditionally for accepted sessions, plus a memory-exhaustion DoS." \
            "Update headscale as soon as a fix ships; until then avoid Tailscale SSH on nodes it manages." \
            "https://tailworm.com/"
    fi
    case "$ctrl" in
        ""|*controlplane.tailscale.com*|*login.tailscale.com*) ;;
        *)
            add_finding "SW-41" "MEDIUM" "Node uses a custom control server (${ctrl})" \
                "Likely headscale — Tailworm reports headscale grants SSH forwarding unconditionally, so per-rule forwarding limits don't apply." \
                "Disable Tailscale SSH on these nodes until headscale is patched." \
                "https://tailworm.com/" ;;
    esac

    # ---------------------------------------------------------- shields up
    local shields
    shields="$(pref_get ShieldsUp)"
    if [ "$shields" = "true" ]; then
        add_finding "SW-50" "INFO" "Shields Up is on" \
            "This node refuses all incoming tailnet connections (including Tailscale SSH)." "" ""
    fi

    return 0
}

# ============================================================== REPORTS ====
write_json() {   # write_json FILE JSONL_SOURCE
    local out="$1" src="$2"
    {
        printf '{\n  "tool": "%s",\n  "version": "%s",\n  "generated": "%s",\n' \
            "$PROG" "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '  "summary": {"high": %d, "medium": %d, "low": %d, "info": %d, "pass": %d},\n' \
            "$(grep -c '"severity":"HIGH"' "$src")" "$(grep -c '"severity":"MEDIUM"' "$src")" \
            "$(grep -c '"severity":"LOW"' "$src")" "$(grep -c '"severity":"INFO"' "$src")" \
            "$(grep -c '"severity":"PASS"' "$src")"
        printf '  "findings": [\n'
        awk 'NR>1{print ","} {printf "    %s", $0} END{print ""}' "$src"
        printf '  ]\n}\n'
    } > "$out"
}

json_field() {   # json_field LINE KEY  (flat string fields only)
    printf '%s' "$1" | sed -n "s/.*\"$2\":\"\(\([^\"\\\\]\|\\\\.\)*\)\".*/\1/p" \
        | sed -e 's/\\n/ /g' -e 's/\\"/"/g' -e 's/\\\\/\\/g'
}

write_html() {   # write_html FILE JSONL_SOURCE
    local out="$1" src="$2" line host sev title detail rec ref cls
    local h m l i p
    h=$(grep -c '"severity":"HIGH"' "$src"); m=$(grep -c '"severity":"MEDIUM"' "$src")
    l=$(grep -c '"severity":"LOW"' "$src");  i=$(grep -c '"severity":"INFO"' "$src")
    p=$(grep -c '"severity":"PASS"' "$src")
    {
cat <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sternwatch Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;
--high:#f85149;--med:#d29922;--low:#58a6ff;--info:#39c5cf;--pass:#3fb950}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;padding:24px 16px}
.wrap{max-width:1100px;margin:0 auto}h1{margin:0 0 4px;font-size:22px}
.sub{color:var(--mut);margin-bottom:20px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:10px 16px;min-width:110px}.card b{display:block;font-size:22px}
.card.h b{color:var(--high)}.card.m b{color:var(--med)}.card.l b{color:var(--low)}
.card.i b{color:var(--info)}.card.p b{color:var(--pass)}
.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--mut);
border-radius:6px;padding:12px 14px;margin-bottom:10px}
.f.HIGH{border-left-color:var(--high)}.f.MEDIUM{border-left-color:var(--med)}
.f.LOW{border-left-color:var(--low)}.f.INFO{border-left-color:var(--info)}
.f.PASS{border-left-color:var(--pass)}
.t{font-weight:600}.sev{font-size:11px;font-weight:700;padding:1px 7px;border-radius:10px;
margin-right:8px;border:1px solid currentColor}
.HIGH .sev{color:var(--high)}.MEDIUM .sev{color:var(--med)}.LOW .sev{color:var(--low)}
.INFO .sev{color:var(--info)}.PASS .sev{color:var(--pass)}
.host{color:var(--mut);font-size:12px;float:right}.d{color:var(--mut);margin-top:6px}
.r{margin-top:6px}.r code{background:#0b0f14;padding:1px 5px;border-radius:4px}
a{color:var(--low)}footer{color:var(--mut);font-size:12px;margin-top:24px}
</style></head><body><div class="wrap">
<h1>⚓ Sternwatch Report</h1>
<div class="sub">Tailscale exposure check (Tailworm &amp; 2026 bulletins) · generated $(html_escape "$(date '+%Y-%m-%d %H:%M %Z')") · v${VERSION} · read-only</div>
<div class="cards">
<div class="card h"><b>${h}</b>High</div><div class="card m"><b>${m}</b>Medium</div>
<div class="card l"><b>${l}</b>Low</div><div class="card i"><b>${i}</b>Info</div>
<div class="card p"><b>${p}</b>Pass</div></div>
EOF
        for sev in HIGH MEDIUM LOW INFO PASS; do
            grep "\"severity\":\"$sev\"" "$src" | while IFS= read -r line; do
                host=$(json_field "$line" host); title=$(json_field "$line" title)
                detail=$(json_field "$line" detail); rec=$(json_field "$line" recommendation)
                ref=$(json_field "$line" reference)
                cls="$sev"
                printf '<div class="f %s"><span class="host">%s</span><span class="sev">%s</span><span class="t">%s</span>' \
                    "$cls" "$(html_escape "$host")" "$sev" "$(html_escape "$title")"
                [ -n "$detail" ] && printf '<div class="d">%s</div>' "$(html_escape "$detail")"
                if [ -n "$rec" ] && [ "$sev" != "PASS" ]; then
                    printf '<div class="r">↳ %s</div>' "$(html_escape "$rec")"
                fi
                [ -n "$ref" ] && printf '<div class="d"><a href="%s">%s</a></div>' "$(html_escape "$ref")" "$(html_escape "$ref")"
                printf '</div>\n'
            done
        done
cat <<EOF
<footer>Sternwatch is read-only and checks local node configuration only. Tailnet-wide ACL/grant rules live in the Tailscale admin console and must be reviewed there.</footer>
</div></body></html>
EOF
    } > "$out"
}

print_summary() {   # print_summary JSONL_SOURCE [multi]
    local src="$1" h m l i p hosts
    h=$(grep -c '"severity":"HIGH"' "$src"); m=$(grep -c '"severity":"MEDIUM"' "$src")
    l=$(grep -c '"severity":"LOW"' "$src");  i=$(grep -c '"severity":"INFO"' "$src")
    p=$(grep -c '"severity":"PASS"' "$src")
    printf '\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$C_DIM" "$C_RST"
    printf '%sSummary%s  %sHIGH %d%s  %sMEDIUM %d%s  %sLOW %d%s  %sINFO %d%s  %sPASS %d%s\n' \
        "$C_BLD" "$C_RST" "$C_RED" "$h" "$C_RST" "$C_YEL" "$m" "$C_RST" \
        "$C_BLU" "$l" "$C_RST" "$C_CYN" "$i" "$C_RST" "$C_GRN" "$p" "$C_RST"
    if [ "${2:-}" = "multi" ]; then
        printf '\n%-28s %5s %6s %4s %5s\n' "HOST" "HIGH" "MEDIUM" "LOW" "PASS"
        hosts=$(sed -n 's/.*"host":"\([^"]*\)".*/\1/p' "$src" | sort -u)
        for hh in $hosts; do
            printf '%-28s %s%5d%s %s%6d%s %4d %s%5d%s\n' "$hh" \
                "$C_RED" "$(grep "\"host\":\"$hh\"" "$src" | grep -c '"severity":"HIGH"')" "$C_RST" \
                "$C_YEL" "$(grep "\"host\":\"$hh\"" "$src" | grep -c '"severity":"MEDIUM"')" "$C_RST" \
                "$(grep "\"host\":\"$hh\"" "$src" | grep -c '"severity":"LOW"')" \
                "$C_GRN" "$(grep "\"host\":\"$hh\"" "$src" | grep -c '"severity":"PASS"')" "$C_RST"
        done
    fi
    printf '%sAlso review in the admin console:%s SSH rules (src/dst, action "check", no root,\n' "$C_DIM" "$C_RST"
    printf '%s  forwarding), subnet-route grants, unused devices, key expiry.%s\n' "$C_DIM" "$C_RST"
    if [ "$h" -gt 0 ]; then return 2; elif [ "$m" -gt 0 ]; then return 1; fi
    return 0
}

emit_outputs() {   # emit_outputs SOURCE
    local src="$1"
    [ -n "$JSONL_OUT" ] && cp "$src" "$JSONL_OUT" && [ "$QUIET" -eq 0 ] && printf '%sJSONL:%s %s\n' "$C_DIM" "$C_RST" "$JSONL_OUT"
    [ -n "$JSON_OUT" ]  && write_json "$JSON_OUT" "$src" && [ "$QUIET" -eq 0 ] && printf '%sJSON :%s %s\n' "$C_DIM" "$C_RST" "$JSON_OUT"
    [ -n "$HTML_OUT" ]  && write_html "$HTML_OUT" "$src" && [ "$QUIET" -eq 0 ] && printf '%sHTML :%s %s\n' "$C_DIM" "$C_RST" "$HTML_OUT"
    return 0
}

# ================================================================= MAIN ====
if [ -n "$HOSTS_SPEC" ]; then
    # ------------------------------------------------- multi-host via SSH
    HOST_LIST=""
    case "$HOSTS_SPEC" in
        @*)
            hf="${HOSTS_SPEC#@}"
            [ -r "$hf" ] || { echo "Cannot read hosts file: $hf" >&2; exit 3; }
            HOST_LIST=$(grep -v '^[[:space:]]*#' "$hf" | tr -s ' \t' '\n' | grep -v '^$') ;;
        *)  HOST_LIST=$(printf '%s' "$HOSTS_SPEC" | tr ',' '\n' | grep -v '^$') ;;
    esac
    AGG_FILE="$(mktemp "${TMPDIR:-/tmp}/${PROG}-agg.XXXXXX")" || exit 3
    SELF="$0"
    printf '%s%s⚓ Sternwatch v%s%s — multi-host mode (read-only)\n' "$C_BLD" "$C_CYN" "$VERSION" "$C_RST"
    for target in $HOST_LIST; do
        printf '  %s→%s %-30s ' "$C_BLU" "$C_RST" "$target"
        fv_arg=""
        [ -n "$TAILWORM_FIXED_VERSION" ] && fv_arg="--fixed-version $TAILWORM_FIXED_VERSION"
        # shellcheck disable=SC2086
        res="$(run_t "$SSH_TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout=8 \
                -o StrictHostKeyChecking=accept-new "$target" \
                "bash -s -- --emit-jsonl --timeout $CMD_TIMEOUT $fv_arg" < "$SELF" 2>/dev/null)"
        if [ -z "$res" ]; then
            safe_t="$(json_escape "$target")"
            printf '{"tool":"%s","version":"%s","host":"%s","id":"SW-99","severity":"INFO","title":"Host unreachable or check failed","detail":"SSH to %s failed or timed out after %ss.","recommendation":"","reference":"","timestamp":"%s"}\n' \
                "$PROG" "$VERSION" "$safe_t" "$safe_t" "$SSH_TIMEOUT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$AGG_FILE"
            printf '%sunreachable%s\n' "$C_DIM" "$C_RST"
        else
            printf '%s\n' "$res" | grep '^{"tool":"sternwatch"' >> "$AGG_FILE"
            hc=$(printf '%s\n' "$res" | grep -c '"severity":"HIGH"')
            mc=$(printf '%s\n' "$res" | grep -c '"severity":"MEDIUM"')
            if [ "$hc" -gt 0 ]; then printf '%s%d HIGH%s' "$C_RED" "$hc" "$C_RST"
            elif [ "$mc" -gt 0 ]; then printf '%s%d MEDIUM%s' "$C_YEL" "$mc" "$C_RST"
            else printf '%sclean%s' "$C_GRN" "$C_RST"; fi
            printf '\n'
        fi
    done
    emit_outputs "$AGG_FILE"
    print_summary "$AGG_FILE" multi
    exit $?
fi

# ------------------------------------------------------------ local run
run_checks
rc_checks=$?

if [ "$EMIT_JSONL_STDOUT" -eq 1 ]; then
    cat "$FINDINGS_FILE"
    exit 0
fi

emit_outputs "$FINDINGS_FILE"
print_summary "$FINDINGS_FILE"
rc=$?
[ "$rc_checks" -eq 3 ] && [ "$rc" -eq 0 ] && exit 3
exit "$rc"
