"""GDB tracer: single-steps a C program and writes a Trace JSON (schema: see PROJECT §4).

Run (from tools/gdb-tracer/run_all.sh):
    TRACE_SRC=prog.c TRACE_OUT=prog.gdb-trace.json TRACE_STDOUT=out.txt [TRACE_STDIN=in.txt] \
    gdb -batch -nx -x tracer.py ./prog

Known limits of v1 (documented, not silent):
  * `expr` (sub-expression columns) is always null: GDB has no column info.
  * `explanation` is null: a shared TS post-processing step fills it in.
  * `initialized` is always true: GDB cannot know whether a local was written.
  * Only frames belonging to the user's file are traced; libc frames are skipped.
"""
import base64
import json
import os
import re

import gdb

SRC = os.path.abspath(os.environ["TRACE_SRC"])
OUT = os.environ["TRACE_OUT"]
STDOUT_FILE = os.environ["TRACE_STDOUT"]
STDIN_FILE = os.environ.get("TRACE_STDIN", "/dev/null")
MAX_STEPS = int(os.environ.get("TRACE_MAX_STEPS", "5000"))
MAX_ELEMS = 256

SRC_LINES = open(SRC, encoding="utf-8").read().splitlines()
SECTION_TO_SEGMENT = {".text": "text", ".rodata": "rodata", ".data": "data", ".bss": "bss"}


def hx(n):
    return "0x%x" % n


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def is_user_frame(frame):
    sal = frame.find_sal()
    return sal.symtab is not None and os.path.abspath(sal.symtab.fullname()) == SRC


def split_call_args(line, fname):
    """Source text of each argument in the first `fname(...)` call on `line`."""
    m = re.search(r"\b%s\s*\(" % re.escape(fname), line)
    if not m:
        return []
    args, depth, cur = [], 1, ""
    for ch in line[m.end():]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                break
        if ch == "," and depth == 1:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    return args


class Tracer:
    def __init__(self):
        self.steps = []
        self.heap = []            # block dicts, in allocation order
        self.heap_event = None    # "alloc" | "free" since the last recorded step
        self.ids = []             # frame ids, outermost first
        self.next_frame = 0
        self.prev_leaves = {}
        self.prev_frames = []     # [{function, ...}] innermost first, previous step
        self.sections = {}        # name -> (start, end)
        self.mappings = {}        # "stack"/"heap" -> (start, end)
        self.exit_code = None
        self.signal = None
        self.last_globals = []
        self.last_rodata = []
        self.last_line = 0

    # ---------------------------------------------------------------- memory map
    def read_maps(self):
        self.sections = {}
        for line in gdb.execute("maint info sections", to_string=True).splitlines():
            m = re.search(r"0x([0-9a-f]+)->0x([0-9a-f]+) at 0x[0-9a-f]+:\s+(\.\w+)", line)
            if m and m.group(3) in SECTION_TO_SEGMENT:
                self.sections[m.group(3)] = (int(m.group(1), 16), int(m.group(2), 16))
        self.mappings = {}
        for line in gdb.execute("info proc mappings", to_string=True).splitlines():
            parts = line.split()
            if parts and parts[0].startswith("0x") and parts[-1] in ("[stack]", "[heap]"):
                self.mappings[parts[-1].strip("[]")] = (int(parts[0], 16), int(parts[1], 16))

    def segments_json(self):
        out = {}
        for sec, seg in SECTION_TO_SEGMENT.items():
            if sec in self.sections:
                s, e = self.sections[sec]
                out[seg] = {"start": hx(s), "end": hx(e)}
            else:
                out[seg] = {"start": None, "end": None}
        for seg in ("heap", "stack"):
            if seg in self.mappings:
                s, e = self.mappings[seg]
                out[seg] = {"start": hx(s), "end": hx(e)}
            else:
                out[seg] = {"start": None, "end": None}
        return out

    def segment_of(self, addr):
        for seg in ("stack", "heap"):
            if seg in self.mappings and self.mappings[seg][0] <= addr < self.mappings[seg][1]:
                return seg
        for sec, (s, e) in self.sections.items():
            if s <= addr < e:
                return SECTION_TO_SEGMENT[sec]
        return None

    # ------------------------------------------------------------ value encoding
    def ser(self, val):
        """Recursively serialize a gdb.Value into a plain dict."""
        t = val.type.strip_typedefs()
        c = t.code
        node = {"type": str(val.type), "size": t.sizeof}
        try:
            node["address"] = hx(int(val.address)) if val.address is not None else None
        except gdb.error:
            node["address"] = None
        if c in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_BOOL, gdb.TYPE_CODE_ENUM, gdb.TYPE_CODE_CHAR):
            node["value"] = int(val)
            if t.sizeof == 1 and c in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_CHAR):
                node["display"] = repr(chr(int(val) & 0xFF))
        elif c == gdb.TYPE_CODE_FLT:
            node["value"] = float(val)
        elif c == gdb.TYPE_CODE_PTR:
            node["value"] = hx(int(val))
            node["pointsTo"] = None  # resolved in resolve_pointers()
        elif c == gdb.TYPE_CODE_ARRAY:
            lo, hi = t.range()
            node["value"] = None
            node["elements"] = []
            for i in range(lo, min(hi, lo + MAX_ELEMS - 1) + 1):
                el = self.ser(val[i])
                el["index"] = i
                node["elements"].append(el)
        elif c in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
            node["value"] = None
            node["fields"] = []
            for f in t.fields():
                fv = self.ser(val[f.name])
                fv["name"] = f.name
                fv["offset"] = f.bitpos // 8
                node["fields"].append(fv)
        else:
            node["value"] = str(val)
        return node

    def variable(self, sym, frame, kind, scope):
        val = sym.value(frame) if sym.needs_frame else sym.value()
        node = self.ser(val)
        t = sym.type.strip_typedefs()
        addr = int(val.address) if val.address is not None else None
        segment = self.segment_of(addr) if addr is not None else None
        node.update({
            "name": sym.name,
            "kind": kind,
            "segment": segment,
            "align": min(t.sizeof, 8) if t.sizeof else 1,
            "initialized": True,
            "isConst": sym.type != sym.type.unqualified(),
            "scope": scope,
            "lifetime": "automatic" if kind in ("local", "param") else "static",
        })
        return node

    # ------------------------------------------------------------------- frames
    def user_frames(self):
        """User-file frames, innermost first (stops at the first libc frame)."""
        frames, f = [], gdb.newest_frame()
        while f is not None and is_user_frame(f):
            frames.append(f)
            f = f.older()
        return frames

    def sync_ids(self, depth):
        while len(self.ids) < depth:
            self.ids.append("f%d" % self.next_frame)
            self.next_frame += 1
        del self.ids[depth:]

    def block_scope(self, block, fname):
        lo = gdb.find_pc_line(block.start).line
        hi = gdb.find_pc_line(block.end - 1).line
        if block.function is not None:
            lo = block.function.line
        return {"function": fname, "fromLine": lo, "toLine": hi}

    def frame_variables(self, frame):
        out = []
        try:
            block = frame.block()
        except RuntimeError:
            return out
        fname = frame.name()
        while block is not None and not (block.is_global or block.is_static):
            scope = self.block_scope(block, fname)
            for sym in block:
                if not (sym.is_variable or sym.is_argument):
                    continue
                if sym.is_argument:
                    kind = "param"
                elif sym.addr_class == gdb.SYMBOL_LOC_STATIC:
                    kind = "static_local"
                else:
                    kind = "local"
                try:
                    out.append(self.variable(sym, frame, kind, scope))
                except (gdb.error, RuntimeError):
                    pass
            if block.function is not None:
                break
            block = block.superblock
        return out

    def frame_json(self, frame, idx, frames):
        fid = self.ids[len(frames) - 1 - idx]
        caller = frames[idx + 1] if idx + 1 < len(frames) else None
        rbp = int(frame.read_register("rbp"))
        rsp = int(frame.read_register("rsp"))
        older = frame.older()
        try:
            saved = int.from_bytes(bytes(gdb.selected_inferior().read_memory(rbp, 8)), "little")
        except gdb.error:
            saved = None
        return {
            "frameId": fid,
            "function": frame.name(),
            "callerFrameId": self.ids[len(frames) - 2 - idx] if caller else None,
            "callLine": caller.find_sal().line if caller else None,
            "depth": len(frames) - 1 - idx,
            "frameStart": hx(rsp),
            "frameEnd": hx(rbp + 16),
            "returnAddress": hx(int(older.pc())) if older is not None else None,
            "savedRbp": hx(saved) if saved is not None else None,
            "returnValue": None,
            "variables": self.frame_variables(frame),
        }

    def globals_json(self, frame):
        out, symtab = [], frame.find_sal().symtab
        for block, kind in ((symtab.global_block(), "global"), (symtab.static_block(), "static_global")):
            for sym in block:
                if not sym.is_variable:
                    continue
                try:
                    v = self.variable(sym, None, kind, {"function": None, "fromLine": 1, "toLine": len(SRC_LINES)})
                except (gdb.error, RuntimeError):
                    continue
                if v["isConst"]:
                    v["kind"] = "const"
                v["lifetime"] = "static"
                out.append(v)
        return out

    # ------------------------------------------------------------ rodata strings
    def read_cstring(self, addr):
        buf = b""
        inf = gdb.selected_inferior()
        try:
            while len(buf) < 256:
                b = bytes(inf.read_memory(addr + len(buf), 1))
                if b == b"\0":
                    break
                buf += b
        except gdb.error:
            pass
        return buf

    def collect_rodata(self, nodes, found):
        for n in nodes:
            v = n.get("value")
            if "pointsTo" in n:
                try:
                    a = int(v, 16)
                except (TypeError, ValueError):
                    a = 0
                if a and self.segment_of(a) == "rodata" and a not in found:
                    s = self.read_cstring(a)
                    found[a] = {"address": hx(a), "value": s.decode("utf-8", "replace"), "size": len(s) + 1}
            self.collect_rodata(n.get("elements", []), found)
            self.collect_rodata(n.get("fields", []), found)

    # ---------------------------------------------------------- pointer targets
    def resolve_pointers(self, call_stack, globals_, sp):
        ranges = []  # (start, end, ref)
        for fr in call_stack:
            for v in fr["variables"]:
                if v["address"]:
                    a = int(v["address"], 16)
                    ranges.append((a, a + v["size"], "stack:%s:%s" % (fr["frameId"], v["name"])))
        for v in globals_:
            if v["address"]:
                a = int(v["address"], 16)
                ranges.append((a, a + v["size"], "global:%s" % v["name"]))

        def target(addr):
            if addr == 0:
                return "null"
            for b in self.heap:
                if b["address_int"] <= addr < b["address_int"] + max(b["size"], 1):
                    if b["status"] == "freed":
                        return "dangling"
                    return "heap:%s:%d" % (b["blockId"], addr - b["address_int"])
            seg = self.segment_of(addr)
            if seg == "stack" and addr < sp:
                return "dangling"  # below the stack pointer: that frame was popped
            for s, e, ref in ranges:
                if s <= addr < e:
                    return ref if addr == s else "%s+%d" % (ref, addr - s)
            if seg in ("rodata", "text"):
                return "%s:%s" % (seg, hx(addr))
            return "invalid"

        def walk(n):
            if "pointsTo" in n:
                n["pointsTo"] = target(int(n["value"], 16))
            for c in n.get("elements", []) + n.get("fields", []):
                walk(c)

        for fr in call_stack:
            for v in fr["variables"]:
                walk(v)
        for v in globals_:
            walk(v)

    # ----------------------------------------------------------------- change set
    def leaves(self, call_stack, globals_, heap):
        out = {}

        def walk(path, n):
            kids = n.get("elements", []) + n.get("fields", [])
            if not kids:
                out[path] = n.get("value")
            for i, c in enumerate(n.get("elements", [])):
                walk("%s[%d]" % (path, c["index"]), c)
            for c in n.get("fields", []):
                walk("%s.%s" % (path, c["name"]), c)

        for fr in call_stack:
            for v in fr["variables"]:
                walk("%s.%s" % (fr["frameId"], v["name"]), v)
        for v in globals_:
            walk("global.%s" % v["name"], v)
        for b in heap:
            out["%s.bytes" % b["blockId"]] = b["bytes"]
        return out

    # --------------------------------------------------------------------- heap
    def heap_json(self):
        inf, out = gdb.selected_inferior(), []
        for b in self.heap:
            raw = b""
            try:
                raw = bytes(inf.read_memory(b["address_int"], b["size"]))
            except gdb.error:
                pass
            out.append({
                "blockId": b["blockId"], "address": hx(b["address_int"]), "size": b["size"],
                "allocatedAtLine": b["allocatedAtLine"], "allocator": b["allocator"],
                "status": b["status"], "freedAtLine": b["freedAtLine"],
                "bytes": base64.b64encode(raw).decode(), "view": None,
            })
        return out

    def user_caller_line(self, frame):
        older = frame.older()
        if older is not None and is_user_frame(older):
            return older.find_sal().line
        return None

    def on_alloc(self, addr, size, line, allocator):
        if addr:
            self.heap.append({"blockId": "h%d" % (len(self.heap) + 1), "address_int": addr, "size": size,
                              "allocatedAtLine": line, "allocator": allocator, "status": "allocated",
                              "freedAtLine": None})
            self.heap_event = "alloc"

    def on_free(self, addr, line):
        for b in self.heap:
            if b["address_int"] == addr and b["status"] == "allocated":
                b["status"], b["freedAtLine"] = "freed", line
                self.heap_event = "free"
                return

    # ---------------------------------------------------------------- recording
    def return_value(self, fname):
        sym = gdb.lookup_global_symbol(fname)
        if sym is None:
            return None
        rt = sym.type.target().strip_typedefs()
        if rt.code == gdb.TYPE_CODE_VOID:
            return None
        if rt.code == gdb.TYPE_CODE_FLT:
            reg = "$xmm0.v4_float[0]" if rt.sizeof == 4 else "$xmm0.v2_double[0]"
            return float(gdb.parse_and_eval(reg))
        val = gdb.parse_and_eval("$rax").cast(rt)  # truncates/sign-interprets like the callee's return type
        return hx(int(val)) if rt.code == gdb.TYPE_CODE_PTR else int(val)

    def at_last_line(self, frame):
        """True when `frame` is on its function's closing line (the `}`)."""
        block = frame.block()
        while block.function is None:
            block = block.superblock
        return frame.find_sal().line == gdb.find_pc_line(block.end - 1).line

    def advance(self, frames):
        """Move to the next recordable point.

        `step` skips the caller's mid-line resume point after a return, so on the
        closing line we single-instruction-step until the frame is popped. That
        stops *inside* the caller's line, which is exactly where it resumes."""
        depth = len(frames)
        if self.at_last_line(frames[0]):
            while True:
                gdb.execute("stepi", to_string=True)
                now = self.user_frames()
                if len(now) < depth:
                    return
        gdb.execute("step", to_string=True)
        while not is_user_frame(gdb.newest_frame()):  # stepped into a libc function with line info
            gdb.execute("finish", to_string=True)
            f = gdb.newest_frame()
            if f.find_sal().pc != f.pc():             # mid-line: finish the statement; else already on a new line
                gdb.execute("step", to_string=True)

    def record(self):
        frames = self.user_frames()
        if not frames:
            return False
        depth, prev_depth = len(frames), len(self.prev_frames)
        self.sync_ids(depth)
        call_stack = [self.frame_json(f, i, frames) for i, f in enumerate(frames)]
        globals_ = self.globals_json(frames[0])
        line = frames[0].find_sal().line
        sp = int(frames[0].read_register("rsp"))

        event, call_ev, ret_ev = "line", None, None
        if depth > prev_depth and prev_depth > 0:
            event = "call"
            caller_text = SRC_LINES[frames[1].find_sal().line - 1]
            exprs = split_call_args(caller_text, frames[0].name())
            params = [v for v in call_stack[0]["variables"] if v["kind"] == "param"]
            call_ev = {"args": [{"param": p["name"], "value": p["value"],
                                 "fromExpr": exprs[i] if i < len(exprs) else None}
                                for i, p in enumerate(params)]}
        elif depth < prev_depth:
            event = "return"
            val = self.return_value(self.prev_frames[0])
            ret_ev = {"value": val, "toFrameId": call_stack[0]["frameId"], "resumeLine": line}
        elif self.heap_event:
            event = self.heap_event
        self.heap_event = None

        heap = self.heap_json()
        self.resolve_pointers(call_stack, globals_, sp)
        found = {}
        for fr in call_stack:
            self.collect_rodata(fr["variables"], found)
        self.collect_rodata(globals_, found)

        leaves = self.leaves(call_stack, globals_, heap)
        changed = [k for k, v in leaves.items() if k in self.prev_leaves and self.prev_leaves[k] != v]
        self.prev_leaves = leaves
        self.prev_frames = [f.name() for f in frames]

        self.steps.append({
            "index": len(self.steps), "line": line, "expr": None, "event": event, "explanation": None,
            "stdout": read_text(STDOUT_FILE), "callStack": call_stack,
            "globals": globals_, "rodata": list(found.values()), "heap": heap, "changed": changed,
            "callEvent": call_ev, "returnEvent": ret_ev, "error": None,
        })
        self.last_globals, self.last_rodata, self.last_line = globals_, list(found.values()), line
        return True

    def finish(self, status):
        for b in self.heap:
            if b["status"] == "allocated":
                b["status"] = "leaked"
        err = None
        if self.signal:
            err = {"signal": self.signal, "line": self.last_line}
            status = "runtime_error"
        self.steps.append({
            "index": len(self.steps), "line": self.last_line, "expr": None,
            "event": "error" if err else "exit", "explanation": None,
            "stdout": read_text(STDOUT_FILE), "callStack": [], "globals": self.last_globals,
            "rodata": self.last_rodata, "heap": self.final_heap(), "changed": [],
            "callEvent": None, "returnEvent": {"value": self.exit_code, "toFrameId": None, "resumeLine": None}
            if self.exit_code is not None else None,
            "error": err,
        })
        return status

    def final_heap(self):
        return [{"blockId": b["blockId"], "address": hx(b["address_int"]), "size": b["size"],
                 "allocatedAtLine": b["allocatedAtLine"], "allocator": b["allocator"], "status": b["status"],
                 "freedAtLine": b["freedAtLine"], "bytes": "", "view": None} for b in self.heap]


TR = Tracer()


class AllocFinish(gdb.FinishBreakpoint):
    """Captures the return value of malloc/calloc/realloc."""
    def __init__(self, frame, size, line, allocator, old_ptr):
        super().__init__(frame, internal=True)
        self.size, self.line, self.allocator, self.old_ptr = size, line, allocator, old_ptr

    def stop(self):
        if self.old_ptr:
            TR.on_free(self.old_ptr, self.line)
        TR.on_alloc(int(gdb.parse_and_eval("$rax")), self.size, self.line, self.allocator)
        return False

    def out_of_scope(self):
        pass


class AllocBP(gdb.Breakpoint):
    def __init__(self, name):
        super().__init__(name, internal=True)
        self.fn = name

    def stop(self):
        f = gdb.newest_frame()
        line = TR.user_caller_line(f)
        if line is None:
            return False
        rdi, rsi = int(gdb.parse_and_eval("$rdi")), int(gdb.parse_and_eval("$rsi"))
        if self.fn == "free":
            if rdi:
                TR.on_free(rdi, line)
        elif self.fn == "malloc":
            AllocFinish(f, rdi, line, "malloc", 0)
        elif self.fn == "calloc":
            AllocFinish(f, rdi * rsi, line, "calloc", 0)
        elif self.fn == "realloc":
            AllocFinish(f, rsi, line, "realloc", rdi)
        return False


def on_exit(ev):
    TR.exit_code = getattr(ev, "exit_code", None)


def on_stop(ev):
    if isinstance(ev, gdb.SignalEvent):
        TR.signal = ev.stop_signal


def main():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set debuginfod enabled off")  # never fetch libc sources: keep libc opaque
    gdb.execute("set style enabled off")
    gdb.execute("set disable-randomization on")
    gdb.execute("set exec-wrapper env -i")  # clean env => reproducible stack addresses
    gdb.events.exited.connect(on_exit)
    gdb.events.stop.connect(on_stop)
    open(STDOUT_FILE, "w").close()
    gdb.execute("break main")
    gdb.execute("run < %s > %s" % (STDIN_FILE, STDOUT_FILE), to_string=True)
    TR.read_maps()
    for name in ("malloc", "calloc", "realloc", "free"):
        AllocBP(name)

    status = "ok"
    while True:
        if len(TR.steps) >= MAX_STEPS:
            status = "step_limit"
            break
        try:
            TR.read_maps()  # heap/stack ranges grow while running
            if not TR.record():
                gdb.execute("continue", to_string=True)  # main returned into libc: run to exit
            else:
                TR.advance(TR.user_frames())
        except gdb.error:
            break
        if TR.exit_code is not None or TR.signal:
            break
    status = TR.finish(status)

    src_text = "\n".join(SRC_LINES)
    trace = {
        "source": "gdb-precomputed", "status": status, "diagnostics": [],
        "program": {"name": os.path.basename(SRC), "code": src_text},
        "stdin": read_text(STDIN_FILE if STDIN_FILE != "/dev/null" else os.devnull),
        "segments": TR.segments_json(), "steps": TR.steps,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(trace, f, indent=1)
    gdb.execute("kill") if TR.exit_code is None else None


main()
