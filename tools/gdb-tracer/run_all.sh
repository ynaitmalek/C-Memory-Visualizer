#!/usr/bin/env bash
# Compile every src/examples/*.c and trace it under GDB.
# Usage: tools/gdb-tracer/run_all.sh [example-name ...]   (default: all)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="$ROOT/build/gdb"
mkdir -p "$BUILD"

# Compiled without -g: it must never be stepped into.
gcc -O0 -c "$ROOT/tools/gdb-tracer/unbuffer.c" -o "$BUILD/unbuffer.o"

names=("$@")
if [ ${#names[@]} -eq 0 ]; then
  for f in "$ROOT"/src/examples/*.c; do names+=("$(basename "$f" .c)"); done
fi

for name in "${names[@]}"; do
  src="$ROOT/src/examples/$name.c"
  stdin="$ROOT/src/examples/$name.stdin"
  [ -f "$stdin" ] || stdin=/dev/null
  echo "==> tracing $name"
  # PIE is kept (default) so segments land at 0x5555555xxxxx with ASLR off.
  gcc -g -O0 -fno-omit-frame-pointer -fno-stack-protector \
      "$src" "$BUILD/unbuffer.o" -o "$BUILD/$name" -lm
  TRACE_SRC="$src" TRACE_STDIN="$stdin" \
  TRACE_STDOUT="$BUILD/$name.stdout" \
  TRACE_OUT="$ROOT/src/examples/$name.gdb-trace.json" \
    gdb -batch -nx -x "$ROOT/tools/gdb-tracer/tracer.py" "$BUILD/$name" >"$BUILD/$name.gdb.log" 2>&1 \
    || { echo "GDB failed for $name:"; tail -30 "$BUILD/$name.gdb.log"; exit 1; }
done
