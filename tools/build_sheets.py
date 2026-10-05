"""Build the Spreadsheet-Method tables from the raw Ghidra export.

Inputs  (../Risk/export/):     functions_raw.csv calls.csv strings.csv globals.csv sections.csv
                               instructions.csv memory.csv registers.csv raw_c/*.c
        (../Risk/extracted/):  symbols.csv (find_stubs.py), disc_files.csv (psx_extract.py), SLUS_006.16
Outputs (sheets/):  meta.csv functions.csv units.csv symbols.csv calls.csv strings.csv globals.csv
                    sections.csv instructions.csv memory.csv registers.csv disc_files.csv
        (src/units/, src/raw_c/): one C file per unit, projected from the sheet (regenerable)

The executable has no symbols. PsyQ links the game's objects first, then the startup code
(`__start`) and the Sony libraries, so every function below `__start` is game code and is split
into address-ordered work units of about UNIT_BYTES. Library functions are classified by the
hardware they touch, the BIOS calls they make and the strings they print (libcd, libgpu, libspu,
libpress, libtap, libmcrd, libetc, libapi, libc, libgte, libsnd) and the remaining ones inherit the
library of their neighbours when both sides agree (each library is linked contiguously),
otherwise `psyq/misc`. Re-running preserves the
hand-edited columns (name, unit, status, owner, notes) of sheets/functions.csv, so the sheet stays
the source of truth across re-exports. sheets/manual_names.csv (addr, name, status, evidence)
holds names identified by hand and always wins.
"""
import csv
import hashlib
import os
import re
import shutil
import struct
from collections import Counter, defaultdict
from pathlib import Path

csv.field_size_limit(1 << 30)
OUT = Path(__file__).resolve().parent.parent                   # RiskDecomp/
WORK = Path(os.environ.get("RISK_WORK", OUT.parent / "Risk"))  # Ghidra project, export/, extracted/
EXP, EX, SHEETS, SRC = WORK / "export", WORK / "extracted", OUT / "sheets", OUT / "src" / "units"
STATUSES = ["raw", "named", "typed", "clean", "verified"]
EXE = "SLUS_006.16"
UNIT_BYTES = 0x2000

# Evidence -> library, checked in order on each library function's decompiled C.
LIB_RULES = [
    ("libpress", [r"1f801820", r"1f801824", r"MDEC_", r"DecDCT"]),
    ("libcd", [r"1f80180[0-3]", r"CdRead", r"CDROM", r"Cd[A-Z][a-z]+", r"track overflow"]),
    ("libspu", [r"1f801c", r"1f801d", r"Spu[A-Z]", r"0xf0000009"]),
    ("libgpu", [r"1f801810", r"1f801814", r"SetGraph", r"DrawSync", r"LoadImage", r"GPU"]),
    ("libtap", [r"1f80104", r"Control TAP", r"0x7f\b"]),
    ("libmcrd", [r"libmcrd", r"0xf4000001", r"0xf0000011", r"_card_", r"bu00", r"firstfile|nextfile"]),
    ("libetc", [r"VSync", r"intr timeout", r"unexpected interrupt", r"HookEntryInt", r"ChangeClearRCnt"]),
    ("libgte", [r"copFunction|setCopControlWord|getCopReg|setCopReg"]),
    ("libapi", [r"syscall\(", r"OpenEvent|EnableEvent|TestEvent|DeliverEvent|SysEnqIntRP"]),
]
BIOS_LIB = {"libc": {"abs", "setjmp", "strcat", "strncat", "strcmp", "strncmp", "strcpy", "strncpy",
                     "strlen", "strstr", "toupper", "memcpy", "memset", "rand", "srand", "malloc",
                     "free", "printf", "memchr", "InitHeap", "bzero", "puts", "exit", "_exit"}}


def read(p):
    with open(p, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write(p, rows, cols):
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def load_memory():
    mem = {}
    for r in read(EXP / "memory.csv"):
        mem[int(r["addr"], 16)] = bytes.fromhex(r["hex"])
    return mem


def word(mem, a):
    base = a & ~63
    blk = mem.get(base)
    if blk is None or (a - base) + 4 > len(blk):
        return None
    return struct.unpack_from("<I", blk, a - base)[0]


def resolve_ptrs(code, mem):
    """Ghidra prints hardware register pointers kept in data as PTR_DAT_xxxxxxxx: append the
    hardware addresses they hold so the library rules can see them."""
    hw = set()
    for m in re.finditer(r"PTR_[A-Za-z_]*?([0-9a-f]{8})\b", code):
        v = word(mem, int(m.group(1), 16))
        if v is not None and 0x1F800000 <= v < 0x1F803000:
            hw.add(f"{v:08x}")
    return code + "\n// hw: " + " ".join(sorted(hw))


def classify(name, code):
    for lib, names in BIOS_LIB.items():
        if name in names:
            return lib
    for lib, pats in LIB_RULES:
        if any(re.search(p, code) for p in pats):
            return lib
    return ""


def main():
    SHEETS.mkdir(parents=True, exist_ok=True)
    funcs = read(EXP / "functions_raw.csv")
    syms = {int(s["addr"], 16): s for s in read(EX / "symbols.csv")}
    prev = {r["addr"]: r for r in read(SHEETS / "functions.csv")} if (SHEETS / "functions.csv").exists() else {}
    start = next(a for a, s in syms.items() if s["name"] == "__start")

    funcs.sort(key=lambda r: int(r["addr"], 16))
    mem = load_memory()
    code = {f["addr"]: resolve_ptrs((EXP / "raw_c" / f"{f['addr'][2:]}.c").read_text(encoding="utf-8"), mem)
            for f in funcs}

    # Library classification with neighbour fill (forward, then backward for the leading gap).
    libs = {}
    for f in funcs:
        a = int(f["addr"], 16)
        if a >= start:
            libs[f["addr"]] = classify(f["name"], code[f["addr"]])
    lib_addrs = [f["addr"] for f in funcs if int(f["addr"], 16) >= start]
    known = [(i, libs[a]) for i, a in enumerate(lib_addrs) if libs[a]]
    for i, a in enumerate(lib_addrs):
        if libs[a]:
            continue
        before = [l for j, l in known if j < i]
        after = [l for j, l in known if j > i]
        p, n = (before[-1] if before else ""), (after[0] if after else "")
        libs[a] = p if p == n and p else "misc"
    libs[f"0x{start:08X}"] = "crt0"

    manual = {}
    if (SHEETS / "manual_names.csv").exists():
        manual = {r["addr"].upper().replace("0X", "0x"): r for r in read(SHEETS / "manual_names.csv")}
    rows = []
    for f in funcs:
        a = int(f["addr"], 16)
        old = prev.get(f["addr"], {})
        man = manual.get(f["addr"])
        if a >= start:
            module = "psyq"
            unit = f"psyq/{libs[f['addr']]}"
            note = "library inferred from hardware/BIOS use or neighbours"
        else:
            module = "game"
            seg = (a - 0x80010000) // UNIT_BYTES * UNIT_BYTES + 0x80010000
            unit = f"game/seg_{seg:08X}"
            note = ""
        name = f["name"]
        status = "raw" if name.startswith(("FUN_", "LAB_", "caseD_")) else "named"
        if a in syms and int(syms[a]["size"] or 0) == 12:
            note = f"BIOS call stub: table {syms[a]['table']} function {syms[a]['number']}"
        if man:
            name, status, note = man["name"], man["status"], man["evidence"]
            old = {k: v for k, v in old.items() if k not in ("name", "status", "notes")}
        rows.append({
            **f,
            "name": old.get("name") or name,
            "module": module,
            "unit": old.get("unit") or unit,
            "status": old.get("status") or status,
            "owner": old.get("owner", ""),
            "notes": old.get("notes") or note,
            "c_path": f"src/raw_c/{f['addr'][2:]}.c",
        })
    fcols = ["addr", "name", "size", "module", "section", "unit", "status", "owner", "calls_out", "called_by",
             "decomp_lines", "decomp_ok", "signature", "c_path", "notes"]
    write(SHEETS / "functions.csv", rows, fcols)

    by_unit = defaultdict(list)
    for r in rows:
        by_unit[r["unit"]].append(r)
    units = []
    for u, rs in by_unit.items():
        st = Counter(r["status"] for r in rs)
        units.append({
            "unit": u, "module": rs[0]["module"], "library": u.split("/")[1] if u.startswith("psyq/") else "",
            "first_addr": rs[0]["addr"], "last_addr": rs[-1]["addr"],
            "n_funcs": len(rs), "total_size": sum(int(r["size"]) for r in rs),
            **{s: st.get(s, 0) for s in STATUSES},
            "owner": "", "src_path": f"src/units/{u.replace('/', '__')}.c",
        })
    units.sort(key=lambda r: int(r["first_addr"], 16))
    write(SHEETS / "units.csv", units, ["unit", "module", "library", "first_addr", "last_addr", "n_funcs",
                                        "total_size", *STATUSES, "owner", "src_path"])

    for name in ["calls.csv", "strings.csv", "globals.csv", "sections.csv", "instructions.csv", "memory.csv",
                 "registers.csv"]:
        shutil.copy(EXP / name, SHEETS / name)
    for name in ["symbols.csv", "disc_files.csv"]:
        shutil.copy(EX / name, SHEETS / name)

    raw = OUT / "src" / "raw_c"
    if raw.exists():
        shutil.rmtree(raw)
    shutil.copytree(EXP / "raw_c", raw)

    # Projection: concatenate each unit's functions into one C file.
    if SRC.exists():
        shutil.rmtree(SRC)
    SRC.mkdir(parents=True)
    for u, rs in by_unit.items():
        with open(OUT / f"src/units/{u.replace('/', '__')}.c", "w", encoding="utf-8") as fh:
            fh.write(f"// unit {u} ({rs[0]['module']}): {len(rs)} functions {rs[0]['addr']}..{rs[-1]['addr']}\n"
                     f"// GENERATED from sheets/functions.csv - edit the sheet, not this file.\n\n")
            for r in rs:
                fh.write((OUT / r["c_path"]).read_text(encoding="utf-8"))
                fh.write("\n")

    exe = (EX / "files" / EXE).read_bytes()
    pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", exe, 0x10)
    sp0 = struct.unpack_from("<I", exe, 0x30)[0]
    cnf = (EX / "files" / "SYSTEM.CNF").read_text(errors="replace")
    write(SHEETS / "meta.csv", [
        {"key": "game_id", "value": "SLUS-00616"},
        {"key": "title", "value": "Risk: The Game of Global Domination (USA)"},
        {"key": "platform", "value": "Sony PlayStation (MIPS R3000A, little endian)"},
        {"key": "engine", "value": "Hasbro Interactive game code + PsyQ 4.x libraries (libapi, libc, libetc, libgpu, "
                                   "libgte, libcd, libspu/libsnd, libpress, libmcrd, libtap)"},
        {"key": "exe", "value": EXE},
        {"key": "entry_point", "value": f"0x{pc0:08X}"},
        {"key": "gp", "value": "0x800A2C80"},
        {"key": "text", "value": f"0x{t_addr:08X}+0x{t_size:X}"},
        {"key": "stack", "value": f"0x{sp0:08X}"},
        {"key": "system_cnf", "value": " ".join(cnf.split())},
        {"key": "exe_sha1", "value": hashlib.sha1(exe).hexdigest()},
        {"key": "exe_size", "value": str(len(exe))},
        {"key": "symbols", "value": "none shipped; BIOS call stubs named by tools/find_stubs.py"},
        {"key": "toolchain", "value": "Ghidra 12.1.4 (ELF wrapper from tools/psx2elf.py, MIPS:LE:32:default) via ghidra-cli 0.2.2"},
    ], ["key", "value"])

    tot = Counter(r["status"] for r in rows)
    lib = Counter(r["unit"] for r in rows if r["module"] == "psyq")
    print(f"{len(rows)} functions, {len(units)} units, status {dict(tot)}")
    print("libraries:", dict(lib))


if __name__ == "__main__":
    main()
