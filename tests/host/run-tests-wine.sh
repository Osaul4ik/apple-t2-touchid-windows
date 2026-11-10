#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds the user-mode protocol library and the test executables with mingw-w64
# and runs them under wine. No WDK, no Visual Studio, no T2 hardware:
#
#   tests/host/run-tests-wine.sh            # build + run everything
#   tests/host/run-tests-wine.sh --no-run   # build only
#
# Needs: x86_64-w64-mingw32-g++ / -gcc / -ar, git, wine (64-bit prefix).
# libplist (the same library vcpkg gives the MSVC build) is fetched at a pinned
# tag and compiled as a static library once; later runs reuse it.
#
# This is a second, independent compiler for the shared user-mode code (MSVC
# stays the one that ships). It exists so the transport / discovery logic and
# the scenario tests against the simulated T2 (tests/ScenarioTests.cpp) can run
# on any Linux box and on a cheap CI runner.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${T2_HOST_OUT:-$HERE/out}"
PLIST_TAG="2.6.0"
RUN=1
[[ "${1:-}" == "--no-run" ]] && RUN=0

CXX=x86_64-w64-mingw32-g++
CC=x86_64-w64-mingw32-gcc
AR=x86_64-w64-mingw32-ar
mkdir -p "$OUT/obj" "$OUT/plist"

# --- libplist (static) -------------------------------------------------------
PLIST_SRC="$OUT/plist/libplist"
PLIST_LIB="$OUT/plist/libplist.a"
if [[ ! -f "$PLIST_LIB" ]]; then
    [[ -d "$PLIST_SRC" ]] || git clone -q --depth 1 --branch "$PLIST_TAG" \
        https://github.com/libimobiledevice/libplist.git "$PLIST_SRC"
    echo '#define PACKAGE_VERSION "'"$PLIST_TAG"'"' > "$OUT/plist/config.h"
    objs=()
    for f in "$PLIST_SRC"/src/*.c "$PLIST_SRC"/libcnary/node.c "$PLIST_SRC"/libcnary/node_list.c; do
        o="$OUT/plist/$(basename "$f" .c).o"
        $CC -O1 -DLIBPLIST_STATIC -DHAVE_CONFIG_H -I"$OUT/plist" -I"$PLIST_SRC/include" \
            -I"$PLIST_SRC/src" -I"$PLIST_SRC/libcnary/include" -c "$f" -o "$o"
        objs+=("$o")
    done
    $AR rcs "$PLIST_LIB" "${objs[@]}"
fi

# --- protocol library ----------------------------------------------------------
CXXFLAGS=(-std=c++17 -O1 -g -Wall -Wno-unknown-pragmas -Wno-unused-function
          -D_WIN32_WINNT=0x0A00 -DUNICODE -D_UNICODE -DNOMINMAX -DLIBPLIST_STATIC
          -municode -I"$ROOT/protocol" -I"$PLIST_SRC/include")
LIBS=(-lws2_32 -liphlpapi -lsetupapi -lrpcrt4 -ladvapi32 -lwtsapi32 -lbcrypt
      -lcrypt32 -lole32 -luuid)

# Source list = the ClCompile items of the MSVC project, so the two builds
# cannot drift apart silently.
mapfile -t PROTO_SRCS < <(grep -o 'ClCompile Include="[^"]*"' "$ROOT/protocol/T2TouchIdProtocol.vcxproj" |
                          sed 's/.*Include="//;s/"$//;s#\\#/#g')
proto_objs=()
for s in "${PROTO_SRCS[@]}"; do
    src="$ROOT/protocol/$s"
    o="$OUT/obj/proto_$(echo "$s" | tr '/' '_' | sed 's/\.cpp$/.o/')"
    if [[ ! -f "$o" || "$src" -nt "$o" || -n "$(find "$ROOT/protocol" -name '*.h' -newer "$o" -print -quit)" ]]; then
        $CXX "${CXXFLAGS[@]}" -c "$src" -o "$o"
    fi
    proto_objs+=("$o")
done
$AR rcs "$OUT/libt2protocol.a" "${proto_objs[@]}"

# --- test executables ------------------------------------------------------------
build_test() {   # name, source...
    local name="$1"; shift
    local objs=()
    for s in "$@"; do
        local o="$OUT/obj/$(basename "$s" .cpp).o"
        $CXX "${CXXFLAGS[@]}" -I"$ROOT/tests" -c "$s" -o "$o"
        objs+=("$o")
    done
    $CXX -municode -static -o "$OUT/$name.exe" "${objs[@]}" "$OUT/libt2protocol.a" "$PLIST_LIB" "${LIBS[@]}"
}

TESTS=(T2TouchIdTests)
build_test T2TouchIdTests "$ROOT/tests/ProtocolTests.cpp"
if [[ -f "$ROOT/tests/ScenarioTests.cpp" ]]; then
    build_test T2TouchIdScenarioTests "$ROOT/tests/ScenarioTests.cpp" "$ROOT/tests/FakeT2.cpp"
    TESTS+=(T2TouchIdScenarioTests)
fi

[[ $RUN == 1 ]] || { echo "built: ${TESTS[*]} in $OUT"; exit 0; }

# --- run -------------------------------------------------------------------------
export WINEDEBUG="${WINEDEBUG:--all}"
rc=0
for t in "${TESTS[@]}"; do
    echo "=== $t"
    if ! (cd "$OUT" && wine "./$t.exe"); then
        echo "=== $t FAILED"
        rc=1
    fi
done
exit $rc
