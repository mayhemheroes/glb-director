#!/usr/bin/env bash
#
# mayhem/test.sh — RUN glb-director's own upstream test suite (prebuilt by mayhem/build.sh).
#
# Upstream's driver is src/glb-director/script/test. The suites that run WITHOUT special
# infrastructure are integrated here:
#   * cli/test-check-config       — upstream C unit tests for check_config() (7 test fns / 21 asserts;
#                                   built by build.sh via the upstream cli Makefile). Behavioral:
#                                   asserted PASS lines + the final "N/N tests passed" summary.
#   * tests/test_rendezvous_table.py (4 tests) — known-answer tests of the siphash rendezvous hashing
#                                   reference implementation.
#   * tests/test_cli_tool.py         (4 tests) — drives cli/glb-director-cli build-config and verifies
#                                   the emitted binary forwarding table byte-for-byte against the
#                                   Python reference (GLBD header, backends, binds, all 65536 rows),
#                                   plus the atomic-write behaviors.
# Skipped upstream suites (documented; they need infra a container build can't provide):
#   * tests/test_director_*.py (19 tests) — require a RUNNING glb-director DPDK/XDP dataplane, root,
#     hugepages, scapy live packet injection (upstream CI runs them in privileged VMs).
#   * tests/config_check.sh, pcap_tests.sh, stub_server_tests.sh, valgrind_check.sh — need the DPDK
#     build of glb-config-check/glb-director-pcap (libdpdk), hugepages, sudo and valgrind.
#   * src/glb-healthcheck HealthResultDampener_test.go — separate Go component (not the fuzzed C code).
#   * src/glb-director-xdp / glb-redirect suites — kernel/XDP components, need privileged kernels.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

GLBDIR="$SRC/src/glb-director"
PASS=0; FAIL=0; SKIP=0

# ---- 1) upstream C unit tests: cli/test-check-config ------------------------------
# The binary prints one "PASS: …"/"FAIL: …" line per assertion and a final "R-F/R tests passed"
# summary. Assert the OUTPUT (counts), not just the exit code.
c_out="$("$GLBDIR/cli/test-check-config" 2>&1)"; c_rc=$?
echo "$c_out"
c_sum="$(printf '%s\n' "$c_out" | grep -oE '[0-9]+/[0-9]+ tests passed' | tail -1)"
if [ -n "$c_sum" ]; then
  c_pass="${c_sum%%/*}"; c_tot="$(printf '%s' "$c_sum" | sed -E 's#^[0-9]+/([0-9]+) .*#\1#')"
  c_fail=$(( c_tot - c_pass ))
  # cross-check the summary against the per-assert PASS lines and the exit code
  c_lines="$(printf '%s\n' "$c_out" | grep -c '^PASS:')"
  if [ "$c_lines" -ne "$c_pass" ] || { [ "$c_rc" -ne 0 ] && [ "$c_fail" -eq 0 ]; }; then
    echo "test-check-config: summary/output mismatch (PASS lines=$c_lines, summary=$c_sum, rc=$c_rc)" >&2
    c_fail=$(( c_fail + 1 ))
  fi
  PASS=$(( PASS + c_pass )); FAIL=$(( FAIL + c_fail ))
else
  echo "test-check-config produced no test summary (rc=$c_rc) — counting as FAILED" >&2
  FAIL=$(( FAIL + 1 ))
fi

# ---- 2) upstream pytest suites runnable without a live DPDK/XDP dataplane ---------
py_out="$(cd "$GLBDIR" && python3 -m pytest -v --tb=short -p no:cacheprovider \
          tests/test_rendezvous_table.py tests/test_cli_tool.py 2>&1)"; py_rc=$?
echo "$py_out"
py_pass="$(printf '%s\n' "$py_out" | grep -oE '[0-9]+ passed'  | tail -1 | grep -oE '[0-9]+' || echo 0)"
py_fail="$(printf '%s\n' "$py_out" | grep -oE '[0-9]+ failed'  | tail -1 | grep -oE '[0-9]+' || echo 0)"
py_err="$(printf  '%s\n' "$py_out" | grep -oE '[0-9]+ error(s)?' | tail -1 | grep -oE '[0-9]+' || echo 0)"
py_skip="$(printf '%s\n' "$py_out" | grep -oE '[0-9]+ skipped' | tail -1 | grep -oE '[0-9]+' || echo 0)"
: "${py_pass:=0}" "${py_fail:=0}" "${py_err:=0}" "${py_skip:=0}"
if [ "$py_rc" -ne 0 ] && [ "$py_fail" -eq 0 ] && [ "$py_err" -eq 0 ]; then
  echo "pytest exited $py_rc without reporting failures (collection error?) — counting as FAILED" >&2
  py_fail=1
fi
PASS=$(( PASS + py_pass )); FAIL=$(( FAIL + py_fail + py_err )); SKIP=$(( SKIP + py_skip ))

emit_ctrf "glb-director-upstream-suite" "$PASS" "$FAIL" "$SKIP"
