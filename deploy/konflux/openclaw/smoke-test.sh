#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Contract smoke tests for a built odh-openshell-sandbox-openclaw image.
# Called by build-local.sh after a build; also runnable by hand.
#
# Usage: smoke-test.sh <image>
#
# PLATFORM defaults from the host's `uname -m` (linux/amd64 or linux/arm64)
# and also accepts linux/x86_64 and linux/aarch64;
# every `podman run` below is pinned to it with --platform, --rm and
# --network none. Requires host `openssl` for the DEFAULT:PQ check's
# throwaway certificate.
#
# `openclaw-start --version` only proves onboarding plus the launcher fast
# path (openclaw.mjs returns before loading config). Agent turns, `tui`,
# `doctor` and `config get/set/validate` are deliberately not run here: EDR
# on maintainers' laptops kills OpenClaw's sqlite workers. Some EDR policies
# also kill any OpenClaw process (exit 137), which fails the version and
# contract-b/c/d checks; run this on a host without such a policy.

if [[ $# -ne 1 ]]; then
    echo "Usage: smoke-test.sh <image>" >&2
    exit 2
fi

image="$1"

case "$(uname -m)" in
    x86_64)  default_platform="linux/amd64" ;;
    aarch64) default_platform="linux/arm64" ;;
    *)       default_platform="linux/$(uname -m)" ;;
esac
PLATFORM="${PLATFORM:-${default_platform}}"
# podman reports OCI arch names; accept the uname aliases build-local.sh takes.
case "${PLATFORM##*/}" in
    x86_64|amd64)  arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)             arch="${PLATFORM##*/}" ;;
esac

workdir=$(mktemp -d)
# mktemp -d defaults to 0700; the containers below run as a UID that only
# maps to an unprivileged subordinate UID on the host (rootless podman), so
# bind-mounted paths under here need to stay traversable by non-owners.
chmod 0755 "${workdir}"
cleanup() {
    rm -rf "${workdir}"
}
trap cleanup EXIT

failures=0

pass() {
    echo "PASS $1"
}

fail() {
    echo "FAIL $1: $2"
    failures=$((failures + 1))
}

podman_run() {
    podman run --rm --platform "${PLATFORM}" --network none "$@"
}

label() {
    podman image inspect "${image}" --format "{{index .Config.Labels \"$1\"}}"
}

# --- arch -------------------------------------------------------------
got_arch=$(podman image inspect "${image}" --format '{{.Architecture}}')
if [[ "${got_arch}" == "${arch}" ]]; then
    pass "arch"
else
    fail "arch" "expected ${arch}, got ${got_arch}"
fi

# --- config -------------------------------------------------------------
got_user=$(podman image inspect "${image}" --format '{{.Config.User}}')
got_entrypoint=$(podman image inspect "${image}" --format '{{.Config.Entrypoint}}')
got_cmd=$(podman image inspect "${image}" --format '{{.Config.Cmd}}')
got_workdir=$(podman image inspect "${image}" --format '{{.Config.WorkingDir}}')
if [[ "${got_user}" == "1000:1000" \
    && ( -z "${got_entrypoint}" || "${got_entrypoint}" == "[]" ) \
    && "${got_cmd}" == "[/usr/local/bin/openclaw-start]" \
    && ( "${got_workdir}" == "/" || -z "${got_workdir}" ) ]]; then
    pass "config"
else
    fail "config" "user=${got_user} entrypoint=${got_entrypoint} cmd=${got_cmd} workdir=${got_workdir}"
fi

# --- labels -------------------------------------------------------------
got_name=$(label name)
got_component=$(label com.redhat.component)
got_harness=$(label io.openshell.sandbox.harness)
got_harness_version=$(label io.openshell.harness.version)
got_s2i1=$(label io.openshift.s2i.scripts-url)
got_s2i2=$(label io.s2i.scripts-url)
got_license=$(label com.redhat.license_terms)
if [[ "${got_name}" == "opendatahub/odh-openshell-sandbox-openclaw" \
    && "${got_component}" == "odh-openshell-sandbox-openclaw-container" \
    && "${got_harness}" == "openclaw" \
    && -n "${got_harness_version}" \
    && -z "${got_s2i1}" \
    && -z "${got_s2i2}" \
    && "${got_license}" == *"#UBI"* ]]; then
    pass "labels"
else
    fail "labels" "name=${got_name} component=${got_component} harness=${got_harness} harness_version=${got_harness_version} s2i1=${got_s2i1} s2i2=${got_s2i2} license=${got_license}"
fi

# --- version --------------------------------------------------------------
if version_out=$(podman_run "${image}" openclaw --version 2>&1); then
    version_rc=0
else
    version_rc=$?
fi
if [[ ${version_rc} -eq 0 && "${version_out}" == "OpenClaw ${got_harness_version} "* ]]; then
    pass "version"
else
    fail "version" "rc=${version_rc} out='${version_out}'"
fi

# --- layout -----------------------------------------------------------
# shellcheck disable=SC2016 # runs inside the container's shell, not the host's
if layout_out=$(podman_run "${image}" bash -c '
set -euo pipefail
if [[ -e /sandbox ]]; then echo "SANDBOX_EXISTS"; exit 1; fi
perm=$(stat -c %a /tmp)
if [[ "$perm" != "1777" ]]; then echo "TMP_PERM=$perm"; exit 1; fi
bad=$(find /usr/local/lib/openclaw \! -perm -o=r -print -quit)
if [[ -n "$bad" ]]; then echo "UNREADABLE=$bad"; exit 1; fi
bad_dir=$(find /usr/local/lib/openclaw -type d \! -perm -o=x -print -quit)
if [[ -n "$bad_dir" ]]; then echo "UNSEARCHABLE=$bad_dir"; exit 1; fi
echo OK
' 2>&1); then
    layout_rc=0
else
    layout_rc=$?
fi
if [[ ${layout_rc} -eq 0 && "${layout_out}" == "OK" ]]; then
    pass "layout"
else
    fail "layout" "rc=${layout_rc} out='${layout_out}'"
fi

# --- pq (DEFAULT:PQ crypto policy honored by Node's system OpenSSL) -------
if config_out=$(podman_run "${image}" cat /etc/crypto-policies/config 2>&1); then
    config_ok=$([[ "${config_out}" == "DEFAULT:PQ" ]] && echo 1 || echo 0)
else
    config_ok=0
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=localhost \
    -keyout "${workdir}/key.pem" -out "${workdir}/cert.pem" >/dev/null 2>&1
chmod 0644 "${workdir}/key.pem" "${workdir}/cert.pem"

cat > "${workdir}/pq-check.mjs" <<'NODEEOF'
import tls from 'node:tls';
import fs from 'node:fs';

const cert = fs.readFileSync('/t/cert.pem');
const key = fs.readFileSync('/t/key.pem');

const server = tls.createServer({ cert, key, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, (socket) => {
  socket.end();
});

server.on('error', (err) => {
  console.error('SERVER_ERROR', err.message);
  process.exit(1);
});

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  const client = tls.connect(
    { host: '127.0.0.1', port, rejectUnauthorized: false, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' },
    () => {
      console.log(client.getEphemeralKeyInfo().name);
      client.end();
      server.close();
    },
  );
  client.on('error', (err) => {
    console.error('CLIENT_ERROR', err.message);
    process.exit(1);
  });
});
NODEEOF
chmod 0644 "${workdir}/pq-check.mjs"

if pq_out=$(podman_run --user 1000:1000 -v "${workdir}:/t:ro,Z" "${image}" node /t/pq-check.mjs 2>&1); then
    pq_group=$(printf '%s\n' "${pq_out}" | tail -n1)
else
    pq_group=""
fi
if [[ ${config_ok} -eq 1 && "${pq_group}" == "X25519MLKEM768" ]]; then
    pass "pq"
else
    fail "pq" "config='${config_out}' node_out='${pq_out}'"
fi

# --- contract (uid 51234, no passwd entry, read-only rootfs) --------------
# One container, so the onboarded config persists in a single /sandbox tmpfs
# across the sub-checks. The inner script never uses `set -e`: it prints a
# PASS/FAIL line per sub-check, and the loop below collects them.
if contract_out=$(podman_run -i --user 51234:51234 --passwd=false --read-only \
    --tmpfs /tmp:rw,mode=1777 --tmpfs /sandbox:rw,mode=1777 \
    -e HOME=/sandbox "${image}" bash -s 2>&1 <<'CONTRACT'
base_url="http://model.example.svc.cluster.local:8000/v1"
cfg=/sandbox/.openclaw/openclaw.json
oneline() { tr '\n' ' ' | cut -c1-400; }

# (a) no MODEL_* env: exit 2 naming MODEL_BASE_URL
err=$(openclaw-start 2>&1 >/dev/null); rc=$?
if [[ $rc -eq 2 && "$err" == *MODEL_BASE_URL* ]]; then
    echo "PASS contract-a"
else
    echo "FAIL contract-a: rc=$rc stderr=$(printf '%s' "$err" | oneline)"
fi

# (b) first run onboards, then execs `openclaw --version`
export MODEL_BASE_URL="$base_url" MODEL_ID=smoke-model CUSTOM_API_KEY=smoke-placeholder
out=$(openclaw-start --version 2>/tmp/b.err); rc=$?
if [[ $rc -eq 0 && "$out" == "OpenClaw "* ]] && grep -q 'openclaw-start: wrote' /tmp/b.err; then
    echo "PASS contract-b"
else
    echo "FAIL contract-b: rc=$rc out=$(printf '%s' "$out" | oneline) stderr=$(oneline </tmp/b.err)"
fi

# (c) the config points at the model through an env-ref API key
c_out=$(node -e '
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const p = cfg.models.providers["openshell-model"];
const ok = p.baseUrl === process.argv[2] &&
    p.api === "openai-completions" &&
    p.apiKey.source === "env" && p.apiKey.id === "CUSTOM_API_KEY" &&
    cfg.agents.defaults.model.primary === "openshell-model/smoke-model";
console.log(ok ? "OK" : "MISMATCH " + JSON.stringify(p));
' "$cfg" "$base_url" 2>&1)
if [[ "$c_out" == "OK" ]]; then
    echo "PASS contract-c"
else
    echo "FAIL contract-c: $(printf '%s' "$c_out" | oneline)"
fi

# (d) a second run leaves the config untouched and does not onboard again
before=$(sha256sum "$cfg" 2>/dev/null | cut -d' ' -f1)
out=$(openclaw-start --version 2>/tmp/d.err); rc=$?
after=$(sha256sum "$cfg" 2>/dev/null | cut -d' ' -f1)
if [[ $rc -eq 0 && -n "$before" && "$before" == "$after" ]] && ! grep -q 'openclaw-start: wrote' /tmp/d.err; then
    echo "PASS contract-d"
else
    echo "FAIL contract-d: rc=$rc before=$before after=$after stderr=$(oneline </tmp/d.err)"
fi

# (e) profile.d is nounset-safe under bash strict mode
if e_out=$(env -i PATH=/usr/bin:/bin bash -c 'set -euo pipefail; . /etc/profile.d/openclaw.sh' 2>&1); then
    echo "PASS contract-e"
else
    echo "FAIL contract-e: $(printf '%s' "$e_out" | oneline)"
fi
CONTRACT
); then
    contract_rc=0
else
    contract_rc=$?
fi
for sub in a b c d e; do
    line=$(printf '%s\n' "${contract_out}" | grep -E "^(PASS|FAIL) contract-${sub}(:|$)" | head -n1 || true)
    if [[ "${line}" == "PASS contract-${sub}" ]]; then
        pass "contract-${sub}"
    elif [[ -n "${line}" ]]; then
        fail "contract-${sub}" "${line#FAIL contract-"${sub}": }"
    else
        fail "contract-${sub}" "no result (container rc=${contract_rc}): $(printf '%s' "${contract_out}" | tr '\n' ' ' | cut -c1-400)"
    fi
done

# --- login-shell (K8s exec-style login shell picks up profile.d) ---------
# shellcheck disable=SC2016 # runs inside the container's shell, not the host's
if login_out=$(podman_run --user 51234:51234 --passwd=false "${image}" \
    env -i HOME=/sandbox PATH=/usr/bin:/bin bash -lc \
    'printf "%s|%s|%s" "$OPENCLAW_NO_AUTO_UPDATE" "$DO_NOT_TRACK" "$(command -v openclaw)"' 2>/dev/null); then
    login_rc=0
else
    login_rc=$?
fi
if [[ ${login_rc} -eq 0 && "${login_out}" == "1|1|/usr/local/bin/openclaw" ]]; then
    pass "login-shell"
else
    fail "login-shell" "rc=${login_rc} out='${login_out}'"
fi

# --- missing-env (default user, no MODEL_* env) ---------------------------
if missing_out=$(podman_run "${image}" openclaw-start 2>&1); then
    missing_rc=0
else
    missing_rc=$?
fi
if [[ ${missing_rc} -eq 2 && "${missing_out}" == *MODEL_BASE_URL* ]]; then
    pass "missing-env"
else
    fail "missing-env" "rc=${missing_rc} out='${missing_out}'"
fi

if [[ ${failures} -gt 0 ]]; then
    echo "smoke-test: ${failures} check(s) failed" >&2
    exit 1
fi
echo "smoke-test: all checks passed"
