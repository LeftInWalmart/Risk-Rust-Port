"""Project the sheets into a Rust workspace.

sheets/instructions.csv (p-code per instruction) -> rust/crates/recomp/part_NN/src/lib.rs
sheets/memory.csv                                 -> rust/crates/risk-recomp/mem/*.bin
sheets/functions.csv + meta.csv + hle.csv         -> rust/crates/risk-recomp/src/table.rs + HLE hooks

Every function becomes `pub fn f_<ADDR>(c: &mut Ctx, entry: u32)`: a loop over a `match` with one
arm per basic block (dense indices -> jump table). Straight-line code inside a block runs without
dispatch; direct branches set the block index; computed jumps and mid-function entries resolve
through a per-function leader table. Block leaders: function entries, every constant branch/call
target, code addresses stored anywhere in the executable image (jump tables, callbacks), the
instruction after any unconditional transfer and the return address of every `setjmp` call (the
BIOS resumes there when an interrupt arrives, see psx-runtime kernel.rs). Branches back to an
earlier address (loops) poll for pending interrupts, so loops waiting on a flag set by an
interrupt handler terminate.

MIPS specifics:
- Ghidra folds each branch's delay slot into the branch's own p-code (`delayslot(1)`), so delay
  slot rows (column `delay` = 1) are skipped; one is only emitted on its own when it is a block
  leader (code jumps straight into it), and the fall-through of the branch before it then goes to
  the instruction after the slot.
- Ghidra's register offsets are remapped onto psx-core's compact register file (REGMAP). $zero
  reads as 0 and writes to it are dropped.
- `mtc0` goes to the runtime (Status changes can unmask an interrupt); COP2 (GTE) register moves
  and commands go to the runtime's GTE; `syscall` and `break` to its kernel.
Generated code is disposable: edit the sheets (or this generator), then rerun.
"""
import csv
import io
import os
import re
import shutil
from collections import defaultdict
from pathlib import Path

csv.field_size_limit(1 << 30)
ROOT = Path(__file__).resolve().parent.parent
SHEETS, RUST = ROOT / "sheets", ROOT / "rust"
CRATES = RUST / "crates"
PARTS = 8
PREFIX = "risk"

VN = re.compile(r"([CRUMX])([0-9a-f]+):(\d+)")
BIN = {
    "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM", "INT_AND", "INT_OR",
    "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS",
    "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
    "BOOL_AND", "BOOL_OR", "BOOL_XOR",
}
UN = {"INT_NEGATE", "INT_2COMP", "INT_ZEXT", "BOOL_NEGATE", "POPCOUNT", "LZCOUNT"}

# Ghidra MIPS register offset -> psx-core register file offset (see psx-core REG_*).
REGMAP = {o: o for o in range(0, 0x80)}
REGMAP.update({0x80: 0x80, 0x3000: 0x84, 0x3004: 0x88, 0x2030: 0x8C, 0x2034: 0x90, 0x2038: 0x94})
COP0_NUM = {0x2030: 12, 0x2034: 13, 0x2038: 14}
ISA_MODE = 0x3F00  # ISAModeSwitch (MIPS16): meaningless on the R3000A, dropped


def read(name):
    with open(SHEETS / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def parse_vn(tok):
    if tok == "_":
        return None
    k, off, size = VN.fullmatch(tok).groups()
    return k, int(off, 16), int(size)


def parse_op(text):
    head, rest = text.split(" = ", 1) if " = " in text else (text, "")
    parts = head.split(" ")
    mnem = parts[0]
    name = None
    if mnem.startswith("CALLOTHER["):
        name = mnem[10:-1]
        mnem = "CALLOTHER"
    out = parse_vn(parts[1]) if len(parts) > 1 else None
    ins = [parse_vn(t) for t in rest.split()] if rest else []
    return mnem, name, out, ins


def write_if_changed(path, data):
    """Only touch files whose content changed, so cargo rebuilds just what changed."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if path.exists() and path.read_bytes() == data:
        return
    path.write_bytes(data)


class Out(io.StringIO):
    """`with Out(path) as fh:` collects text and writes it with write_if_changed on exit."""

    def __init__(self, path):
        super().__init__()
        self.path = path

    def __exit__(self, *exc):
        if exc[0] is None:
            write_if_changed(self.path, self.getvalue())
        return super().__exit__(*exc)


def mask(v, s):
    return v & ((1 << (8 * s)) - 1)


def ends_block(pcode):
    """True if control never falls through past this instruction unconditionally (branch,
    computed jump or return)."""
    for text in pcode.split(" | "):
        m = text.split(" ", 1)[0]
        if m in ("BRANCH", "BRANCHIND", "RETURN"):
            return True
    return False


SETJMP = set()  # entry addresses of the setjmp BIOS stub
ALL_ENTRIES = set()  # every generated function entry (all parts)


def calls_setjmp(text):
    if not text.startswith("CALL "):
        return False
    ins = parse_op(text)[3]
    return bool(ins and ins[0] and ins[0][0] == "M" and ins[0][1] in SETJMP)


def find_leaders(instructions, entries):
    """Global set of block leaders: function entries, constant branch/call targets, the return
    address of setjmp calls and code addresses stored anywhere in the image."""
    code = {int(r["addr"], 16) for r in instructions}
    leaders = set(entries)
    for r in instructions:
        for text in r["pcode"].split(" | "):
            if calls_setjmp(text):
                leaders.add(int(r["addr"], 16) + 8)  # after the jal and its delay slot
            if not text.startswith(("BRANCH ", "CBRANCH ", "CALL ")):
                continue
            ins = parse_op(text)[3]
            if ins and ins[0] and ins[0][0] == "M":
                leaders.add(ins[0][1])
    data_refs = 0
    for r in read("memory.csv"):
        raw = bytes.fromhex(r["hex"])
        for i in range(0, len(raw) - 3, 4):
            w = int.from_bytes(raw[i:i + 4], "little")
            if w in code and w not in leaders:
                leaders.add(w)
                data_refs += 1
    print(f"block leaders: {len(leaders)} ({data_refs} from data references)", flush=True)
    return leaders


class Gen:
    def __init__(self, entries, leaders):
        self.entries = entries          # all function entry addrs (this part)
        self.leaders = leaders          # global block-leader addresses
        self.blk = {}                   # current function: leader address -> block index
        self.cur = 0                    # address of the instruction being translated
        self.extern = set()             # functions of other parts this part calls directly
        self.asm = ""

    def reg(self, off):
        if off not in REGMAP:
            raise ValueError(f"unmapped register offset {off:#x} at {self.cur:#010x} ({self.asm})")
        return REGMAP[off]

    def rd(self, v):
        k, off, s = v
        if k == "C":
            return f"0x{mask(off, s):x}u64"
        if k == "R":
            if off < 4:
                return "0u64"
            return f"(c.r(0x{self.reg(off):x},{s}) as u64)"
        if k == "U":
            return f"u{off:x}"
        return f"(c.ld(0x{off:x},{s}) as u64)"

    def wr(self, v, expr):
        k, off, s = v
        if k == "R" and (off < 4 or off == ISA_MODE):
            return f"let _={expr};" if ("c." in expr) else ""
        if k != "U" and "c." in expr:
            return f"{{let v={expr};{self.wr(v, 'v')}}}"
        if k == "R":
            return f"c.wr(0x{self.reg(off):x},{s},({expr}) as u32);"
        if k == "U":
            return f"u{off:x}={expr};"
        if k == "M":
            return f"c.st(0x{off:x},{s},({expr}) as u32);"
        raise ValueError(v)

    def branch(self, target, idx, own, relative):
        k, off, s = target
        if k == "C":  # relative to this instruction's p-code ops
            rel = off - (1 << 32) if off >= 1 << 31 else off
            relative[0] = True
            return f"i={idx + rel};continue;"
        if off in own and off in self.blk:
            # Loop back-edge: poll for interrupts like the CPU would (see Ctx::poll).
            poll = "c.poll();" if off <= self.cur else ""
            return f"{poll}b={self.blk[off]};continue 'f;"
        d = self.direct(off)
        return f"{d};return;" if d else f"c.call(0x{off:x});return;"

    def direct(self, off):
        """Rust call expression for a direct call to the function entry `off`, or None."""
        if off in self.entries:
            return f"f_{off:08X}(c,0x{off:x})"
        if off in ALL_ENTRIES:
            # Another part: linked by symbol name (#[no_mangle]), skipping the dispatcher.
            self.extern.add(off)
            return f"unsafe{{f_{off:08X}(c,0x{off:x})}}"
        return None

    def call(self, off):
        d = self.direct(off)
        return f"{d};" if d else f"c.call(0x{off:x});"

    def callother(self, name, out, ins):
        asm = self.asm.split(" ", 1)[0].lstrip("_")
        if name == "setISAMode":
            return ""
        if name == "syscall":
            return f"c.syscall(({self.rd(ins[0])}) as u32);"
        if name == "trap":
            return f"c.brk(({self.rd(ins[0])}) as u32);"
        if name in ("setCopReg", "getCopReg", "setCopControlWord", "getCopControlWord", "copFunction"):
            cop = ins[0][1]
            if name == "copFunction":
                return f"c.gte_cmd(({self.rd(ins[1])}) as u32);"
            sel = ins[1]
            if cop == 0:
                if name != "setCopReg" or sel[0] != "R" or sel[1] not in COP0_NUM:
                    raise ValueError(f"unsupported COP0 access {name} {sel} at {self.cur:#x}")
                return f"c.mtc0({COP0_NUM[sel[1]]},({self.rd(ins[2])}) as u32);"
            if cop != 2:
                raise ValueError(f"coprocessor {cop} access at {self.cur:#x}")
            # lwc2/swc2 name the GTE register with a GPR varnode (its index); mtc2/mfc2/ctc2/cfc2
            # with the 16-bit immediate (rd << 11).
            if sel[0] == "R":
                n = sel[1] // 4
            elif asm in ("lwc2", "swc2"):
                n = sel[1]
            else:
                n = sel[1] >> 11
            if name == "setCopReg":
                return f"c.gte_write({n},({self.rd(ins[2])}) as u32);"
            if name == "setCopControlWord":
                return f"c.gte_cwrite({n},({self.rd(ins[2])}) as u32);"
            if name == "getCopReg":
                return self.wr(out, f"(c.gte_read({n}) as u64)")
            return self.wr(out, f"(c.gte_cread({n}) as u64)")
        args = ",".join(f"({self.rd(v)}) as u32" for v in ins)
        call = f'c.intrinsic("{name}",&[{args}])'
        return self.wr(out, f"({call} as u64)") if out else call + ";"

    def op(self, text, idx, own, relative):
        mnem, name, out, ins = parse_op(text)
        if mnem == "COPY":
            return self.wr(out, self.rd(ins[0]))
        if mnem == "LOAD":
            return self.wr(out, f"(c.ld(({self.rd(ins[0])}) as u32,{out[2]}) as u64)")
        if mnem == "STORE":
            a, v = self.rd(ins[0]), self.rd(ins[1])
            if "c." in a + v:
                return f"{{let a=({a}) as u32;let v=({v}) as u32;c.st(a,{ins[1][2]},v);}}"
            return f"c.st(({a}) as u32,{ins[1][2]},({v}) as u32);"
        if mnem in BIN:
            return self.wr(out, f"{mnem.lower()}({self.rd(ins[0])},{self.rd(ins[1])},{ins[0][2]})")
        if mnem in UN:
            return self.wr(out, f"{mnem.lower()}({self.rd(ins[0])},{ins[0][2]})")
        if mnem == "INT_SEXT":
            return self.wr(out, f"mask(int_sext({self.rd(ins[0])},{ins[0][2]}),{out[2]})")
        if mnem == "SUBPIECE":
            return self.wr(out, f"subpiece({self.rd(ins[0])},{ins[1][1]},{out[2]})")
        if mnem == "PIECE":
            return self.wr(out, f"piece({self.rd(ins[0])},{self.rd(ins[1])},{ins[1][2]})")
        if mnem == "BRANCH":
            return self.branch(ins[0], idx, own, relative)
        if mnem == "CBRANCH":
            return f"if {self.rd(ins[1])}!=0{{{self.branch(ins[0], idx, own, relative)}}}"
        if mnem == "BRANCHIND":
            return (f"{{let t=({self.rd(ins[0])}) as u32;let k=blk(t);"
                    f"if k!=0{{b=k;continue 'f;}}c.call(t);return;}}")
        if mnem == "CALL":
            k, off, _ = ins[0]
            return self.call(off) if k == "M" else f"c.call(({self.rd(ins[0])}) as u32);"
        if mnem == "CALLIND":
            return f"c.call(({self.rd(ins[0])}) as u32);"
        if mnem == "RETURN":
            return "return;"
        if mnem == "CALLOTHER":
            return self.callother(name, out, ins)
        if mnem == "UNIMPLEMENTED":
            # Data Ghidra disassembled (a word between libraries): never reached in practice.
            return f"c.brk(0xDEAD);return;"
        raise ValueError(f"unhandled p-code op {mnem} at {self.cur:#x}")

    def instruction(self, ins, own):
        self.cur = int(ins["addr"], 16)
        self.asm = ins["asm"]
        ops = [p for p in ins["pcode"].split(" | ") if p]
        uniq = sorted({int(m.group(2), 16) for m in VN.finditer(" | ".join(ops)) if m.group(1) == "U"})
        relative = [False]
        body = [self.op(o, i, own, relative) for i, o in enumerate(ops)]
        decl = "".join(f"let mut u{u:x}=0u64;" for u in uniq)
        if relative[0]:
            arms = "".join(f"{i}=>{{{b}i={i + 1};}}" for i, b in enumerate(body))
            return f"{{{decl}let mut i:i64=0;loop{{match i{{{arms}_=>break}}}}}}"
        return "{" + decl + "".join(body) + "}"

    def function(self, entry, name, rows):
        own = {int(r["addr"], 16) for r in rows}
        delay_of = {}  # branch address -> its delay-slot row
        for k, r in enumerate(rows):
            if r["delay"] == "1" and k > 0:
                delay_of[int(rows[k - 1]["addr"], 16)] = r
        # Rows to emit: everything but delay slots, except delay slots that are leaders.
        emit = [r for r in rows if r["delay"] != "1" or int(r["addr"], 16) in self.leaders]
        # Block leaders inside this function.
        lead, prev_nxt, after_jump = [], None, False
        for r in emit:
            a = int(r["addr"], 16)
            if a == entry or a in self.leaders or after_jump or prev_nxt != a:
                lead.append(a)
            after_jump = ends_block(r["pcode"]) or r["delay"] == "1"
            prev_nxt = a + (8 if a in delay_of else 4)
            if r["delay"] == "1":
                prev_nxt = a + 4
        self.blk = {a: i + 1 for i, a in enumerate(lead)}
        lead_set = set(lead)
        table = ",".join(f"0x{a:x}=>{i + 1}" for i, a in enumerate(lead))
        lines = [f"/// {name} ({len(rows)} instructions, {len(lead)} blocks)",
                 f"#[unsafe(no_mangle)]\npub fn f_{entry:08X}(c:&mut Ctx,entry:u32){{if c.enter(0x{entry:x},entry){{return;}}",
                 f"fn blk(t:u32)->usize{{match t{{{table},_=>0}}}}",
                 (f"let mut b:usize=if entry==0x{entry:x}{{{self.blk[entry]}}}else{{blk(entry)}};"
                  if entry in self.blk else "let mut b:usize=blk(entry);"),
                 f"if b==0{{c.block_miss(0x{entry:x},entry);return;}}",
                 "'f:loop{match b{"]
        for k, r in enumerate(emit):
            a = int(r["addr"], 16)
            nxt = a + (8 if a in delay_of else 4)
            if r["delay"] == "1":
                nxt = a + 4
            if a in lead_set:
                lines.append(f"{self.blk[a]}=>{{")
            asm = r["asm"] + (f" ; {delay_of[a]['asm']}" if a in delay_of else "")
            lines.append(f"// {a:08X} {asm}\n{self.instruction(r, own)}")
            last = k + 1 == len(emit) or int(emit[k + 1]["addr"], 16) in lead_set
            if last:
                # Fall through into the next block (or out of the function: tail-call it).
                if nxt in self.blk:
                    lines.append(f"b={self.blk[nxt]};continue 'f;}}")
                else:
                    lines.append(f"c.call(0x{nxt:x});return;}}")
        lines.append("_=>return}}}")
        return "\n".join(lines)


# Optimisation level for the generated parts in dev builds (see the workspace profile comment).
PART_OPT = int(os.environ.get("RISK_PART_OPT", "3"))


def main():
    funcs = {int(r["addr"], 16): r for r in read("functions.csv")}
    meta = {r["key"]: r["value"] for r in read("meta.csv")}
    hle = [(int(r["addr"], 16), r["name"]) for r in read("hle.csv") if r["addr"]]
    by_func = defaultdict(list)
    orphan_entry = None
    prev_end = None
    print("reading instructions.csv ...", flush=True)
    instructions = read("instructions.csv")
    for r in instructions:
        a = int(r["addr"], 16)
        if r["func"]:
            f = int(r["func"], 16)
            orphan_entry = None
        else:
            # Code outside any Ghidra function (pointer-only callbacks): group contiguous runs.
            if orphan_entry is None or a != prev_end:
                orphan_entry = a
            f = orphan_entry
        prev_end = a + 4
        by_func[f].append(r)
    for rows in by_func.values():
        rows.sort(key=lambda r: int(r["addr"], 16))

    entries = sorted(by_func)
    SETJMP.update(a for a, r in funcs.items() if r["name"] == "setjmp")
    ALL_ENTRIES.update(by_func)
    leaders = find_leaders(instructions, entries)
    del instructions
    total = sum(len(v) for v in by_func.values())
    per_part = total / PARTS
    parts, cur, cnt = [], [], 0
    for e in entries:
        cur.append(e)
        cnt += len(by_func[e])
        if cnt >= per_part * (len(parts) + 1) and len(parts) < PARTS - 1:
            parts.append(cur)
            cur = []
    parts.append(cur)

    recomp = CRATES / "recomp"
    keep = {f"part_{n:02}" for n in range(len(parts))}
    if recomp.exists():
        for stale in recomp.iterdir():
            if stale.name not in keep:
                shutil.rmtree(stale)
    members = []
    table = []
    for n, part in enumerate(parts):
        crate = f"{PREFIX}-part-{n:02}"
        d = recomp / f"part_{n:02}"
        (d / "src").mkdir(parents=True, exist_ok=True)
        members.append(f"crates/recomp/part_{n:02}")
        write_if_changed(d / "Cargo.toml",
            f'[package]\nname = "{crate}"\nversion = "0.1.0"\nedition = "2024"\n\n'
            f'[dependencies]\npsx-core = {{ path = "../../psx-core" }}\n')
        g = Gen(set(part), leaders)
        with Out(d / "src" / "lib.rs") as fh:
            fh.write("//! GENERATED by tools/gen_rust.py from sheets/instructions.csv. Do not edit.\n"
                     "#![allow(unused, unreachable_code, non_snake_case, unused_parens, clippy::all)]\n"
                     "use psx_core::{Ctx, ops::*};\n\n")
            fh.write("pub static FUNCS: &[(u32, u32, fn(&mut Ctx, u32))] = &[\n")
            for e in part:
                rows = by_func[e]
                end = max(int(r["addr"], 16) + 4 for r in rows)
                fh.write(f"    (0x{e:x}, 0x{end:x}, f_{e:08X}),\n")
                name = funcs[e]["name"] if e in funcs else f"orphan_{e:08X}"
                table.append((e, name))
            fh.write("];\n\n")
            for e in part:
                name = funcs[e]["name"] if e in funcs else f"orphan_{e:08X} (code outside any function)"
                fh.write(g.function(e, name, by_func[e]) + "\n\n")
            # Functions of other parts called directly (resolved by the linker).
            fh.write('unsafe extern "Rust" {\n')
            for e in sorted(g.extern):
                fh.write(f"    fn f_{e:08X}(c: &mut Ctx, entry: u32);\n")
            fh.write("}\n")
        print(f"{crate}: {len(part)} functions", flush=True)

    # Memory image from memory.csv: the executable image (one block).
    top = CRATES / f"{PREFIX}-recomp"
    mem = top / "mem"
    mem.mkdir(parents=True, exist_ok=True)
    blobs = defaultdict(bytearray)
    starts = {}
    for r in read("memory.csv"):
        sec = r["section"].lstrip(".")
        starts.setdefault(sec, int(r["addr"], 16))
        blobs[sec] += bytes.fromhex(r["hex"])
    for sec, data in blobs.items():
        write_if_changed(mem / f"{sec}.bin", bytes(data))

    deps = "\n".join(f'{PREFIX}-part-{n:02} = {{ path = "../recomp/part_{n:02}" }}' for n in range(len(parts)))
    (top / "src").mkdir(parents=True, exist_ok=True)
    write_if_changed(top / "Cargo.toml",
        f'[package]\nname = "{PREFIX}-recomp"\nversion = "0.1.0"\nedition = "2024"\n\n'
        f'[dependencies]\npsx-core = {{ path = "../psx-core" }}\npsx-runtime = {{ path = "../psx-runtime" }}\n{deps}\n')
    with Out(top / "src" / "table.rs") as fh:
        fh.write("//! GENERATED by tools/gen_rust.py. Do not edit.\nuse psx_core::Ctx;\n\n")
        fh.write(f"pub const ENTRY_POINT: u32 = {meta['entry_point']};\n")
        fh.write(f"pub const FUNCTION_COUNT: usize = {len(table)};\n")
        fh.write("pub static SECTIONS: &[(u32, &[u8])] = &[\n")
        for sec, start in starts.items():
            fh.write(f'    (0x{start:08x}, include_bytes!("../mem/{sec}.bin")),\n')
        fh.write("];\n\npub fn parts() -> [&'static [(u32, u32, fn(&mut Ctx, u32))]; %d] {\n    [\n" % len(parts))
        for n in range(len(parts)):
            fh.write(f"        {PREFIX}_part_{n:02}::FUNCS,\n")
        fh.write("    ]\n}\n\n/// Functions handled by psx_runtime::hle (from sheets/hle.csv).\n")
        fh.write("pub static HLE: &[(u32, &str)] = &[\n")
        for e, name in hle:
            fh.write(f'    (0x{e:08x}, "{name}"),\n')
        fh.write("];\n\npub static NAMES: &[(u32, &str)] = &[\n")
        for e, name in sorted(table):
            fh.write(f'    (0x{e:08x}, "{name}"),\n')
        fh.write("];\n")

    pkgs = ["psx-runtime", f"{PREFIX}-recomp", f"{PREFIX}-bevy"]
    write_if_changed(RUST / "Cargo.toml",
        '[workspace]\nresolver = "3"\nmembers = [\n    "crates/psx-core",\n    "crates/psx-runtime",\n'
        f'    "crates/{PREFIX}-recomp",\n    "crates/{PREFIX}-bevy",\n' + "".join(f'    "{m}",\n' for m in members) + "]\n\n"
        "# The game is played from this profile (play.bat). Debug assertions and integer overflow\n"
        "# checks would sit on every guest instruction and throughout Bevy, so they are off. No debug\n"
        "# info (panics still print their message, just without file:line backtraces).\n"
        "[profile.dev]\nopt-level = 1\ndebug = false\ndebug-assertions = false\noverflow-checks = false\n\n"
        "# Bevy and the runtime are small and hot: optimize them even in dev builds.\n"
        '[profile.dev.package."*"]\nopt-level = 3\n\n'
        "# Workspace members are not covered by the wildcard above.\n"
        + "".join(f'[profile.dev.package.{p}]\nopt-level = 3\n\n' for p in pkgs) +
        "# psx-core is the per-instruction hot path; inline and optimize it fully.\n"
        '[profile.dev.package.psx-core]\nopt-level = 3\n\n'
        "# The generated parts: full optimization with few codegen units (inlining between guest\n"
        "# functions); RISK_PART_OPT=1 builds faster but runs slower.\n"
        + "".join(f'[profile.dev.package.{PREFIX}-part-{n:02}]\nopt-level = {PART_OPT}\ndebug = false\ncodegen-units = 16\nincremental = false\n\n' for n in range(len(parts)))
        + "[profile.release]\ncodegen-units = 16\n")
    print(f"{len(table)} functions in {len(parts)} parts, {total} instructions")


if __name__ == "__main__":
    main()
