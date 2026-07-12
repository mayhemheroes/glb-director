#!/usr/bin/env bash
#
# mayhem/build.sh — build glb-director's fuzz targets + upstream test suite.
#
# Fuzz targets (sanitized, DWARF-3, into /mayhem):
#   /mayhem/fuzz_glb_log_info             libFuzzer harness over glb_log_info() (log.h / jansson JSON log build)
#   /mayhem/fuzz_glb_log_info-standalone  same harness linked against $STANDALONE_FUZZ_MAIN (run-once reproducer)
#   /mayhem/glb-director-cli              file-input CLI target: `build-config <json> <bin>` — the forwarding
#                                         table builder (jansson parse + siphash rendezvous hashing)
# Test-suite build (NORMAL flags, via the upstream cli Makefile, left in-tree where the tests expect):
#   src/glb-director/cli/glb-director-cli    used by tests/test_cli_tool.py
#   src/glb-director/cli/test-check-config   C unit tests for check_config() (glb_fwd_config.c)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs from the ENVIRONMENT (overridable). SANITIZER_FLAGS uses `=` (no colon) on purpose —
# an explicit EMPTY value (--build-arg SANITIZER_FLAGS=) is honored and builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
GLBDIR="$SRC/src/glb-director"

# 1) Sanitized, instrumented FUZZ build of the CLI forwarding-table builder (the project code under
#    fuzz: cli/main.c + siphash24.c + jansson). Mirrors the upstream cli Makefile's glb-director-cli
#    recipe, plus $SANITIZER_FLAGS/$DEBUG_FLAGS so the fuzzed project code is instrumented.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -Wall -DCLI_MODE \
    -I"$GLBDIR" -I"$SRC/src" \
    "$GLBDIR/cli/main.c" "$GLBDIR/siphash24.c" \
    -ljansson \
    -o /mayhem/glb-director-cli

# 2) libFuzzer harness over glb_log_info(), twice: fuzzer + standalone run-once reproducer.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    -I"$GLBDIR" \
    "$SRC/mayhem/fuzz_glb_log_info.cpp" \
    -ljansson \
    -o /mayhem/fuzz_glb_log_info

$CC -c $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    -I"$GLBDIR" \
    "$SRC/mayhem/fuzz_glb_log_info.cpp" /tmp/standalone_main.o \
    -ljansson \
    -o /mayhem/fuzz_glb_log_info-standalone

# 3) Upstream TEST-SUITE build with the project's NORMAL flags (a clean, independent build via the
#    upstream cli Makefile; gcc, no sanitizers) — mayhem/test.sh only RUNS these, never compiles:
#      cli/glb-director-cli   (tests/test_cli_tool.py drives it)
#      cli/test-check-config  (check_config() unit tests)
make -C "$GLBDIR/cli" glb-director-cli test-check-config
