#!/usr/bin/env bash
# Clipper2/mayhem/test.sh — RUN the GoogleTest suite built by mayhem/build.sh (normal flags).
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

bindir="$SRC/build-tests"
bin="$bindir/ClipperTests"
[ -x "$bin" ] || { echo "missing ClipperTests — run mayhem/build.sh first" >&2; emit_ctrf "gtest" 0 1; exit 2; }

# Fixture files (Lines.txt, etc.) are copied into the CMake binary dir by build.sh.
out="$(cd "$bindir" && "$bin" 2>&1)"; rc=$?
echo "$out"

passed=$(printf '%s\n' "$out" | sed -n 's/.*\[\s*PASSED\s*\]\s*\([0-9][0-9]*\) tests.*/\1/p' | tail -1)
failed=$(printf '%s\n' "$out" | sed -n 's/.*\[\s*FAILED\s*\]\s*\([0-9][0-9]*\) tests.*/\1/p' | tail -1)
skipped=$(printf '%s\n' "$out" | sed -n 's/.*\[\s*SKIPPED\s*\]\s*\([0-9][0-9]*\) tests.*/\1/p' | tail -1)

: "${passed:=0}"; : "${failed:=0}"; : "${skipped:=0}"
total=$((passed + failed + skipped))

# Behavioral anchor: a neutered exit(0) binary prints no gtest summary.
MIN_TESTS=40
if [ "$rc" -ne 0 ] || [ "$failed" -gt 0 ] || [ "$total" -lt "$MIN_TESTS" ]; then
  echo "behavioral check failed: total=$total passed=$passed failed=$failed (need >=$MIN_TESTS tests)" >&2
  emit_ctrf "gtest" "$passed" "$failed" "$skipped"
  exit 1
fi

emit_ctrf "gtest" "$passed" "$failed" "$skipped"
