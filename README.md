# RiskDecomp: Risk – The Game of Global Domination (SLUS-00616, PlayStation), Spreadsheet Method

The CSVs in `sheets/` are the **single source of truth** for the whole game executable
(`SLUS_006.16`). Everything else is a projection: `src/` (Ghidra C, for reading) and `rust/`
(compilable Rust, for running) are generated from the sheets and never edited by hand.

```
Risk - The Game of Global Domination (USA).cue / (Track 1).bin / (Track 2).bin
   │ tools/psx_extract.py   (ISO9660 over raw 2352-byte MODE2 sectors → files + disc_files.csv)
   ▼
../Risk/extracted/files/  SLUS_006.16, SYSTEM.CNF, RISK/... (form-2 XA/STR streams are only listed)
   │ tools/psx2elf.py       (PS-X EXE → ELF32 MIPS LE so Ghidra imports it as MIPS:LE:32:default)
   │ tools/find_stubs.py    (names the 64 BIOS call stubs A0h/B0h/C0h → symbols.csv)
   ▼
SLUS_006.16.elf ──ghidra-cli import──► ../Risk/ghidra/RISK.gpr
   │ SetGp.java (gp = 0x800A2C80) → ApplySymbols.java → analyze → FixNoReturn.java →
   │ CreateGapFunctions.java (code range only) → ExportPcode.java → ExportSheets.java
   ▼
../Risk/export/ ──tools/build_sheets.py──► sheets/*.csv ──► src/units/*.c (readable C)
                        tools/resolve_hle.py (hle.csv addresses)
                                         └─tools/gen_rust.py──► rust/ (Bevy app)
```

## This repository

Only the tools, the hand-written runtime / Bevy app, the tests and the hand-curated sheets
(`hle.csv`, `manual_names.csv`, `meta.csv`) are published. Everything generated from the game's
executable contains Sony's and Hasbro Interactive's code and data, so it is not included: the other
sheets, `src/` (Ghidra C), the recompiled crates `rust/crates/recomp/`, the memory image
`rust/crates/risk-recomp/mem/`, the dispatch table `risk-recomp/src/table.rs` and the generated
manifests (`rust/Cargo.toml`, `rust/crates/risk-recomp/Cargo.toml`). Generate them from your own
disc with the steps in **Rebuilding from the disc** below, then run `play.bat`.

## Playing

Run **`play.bat`**. The first run builds everything, later runs start in seconds. The disc image
is read from `RISK_DISC`, which defaults to
`%USERPROFILE%\Downloads\Emus\PS1\Risk - The Game of Global Domination (USA)\Risk - The Game of Global Domination (USA)\Risk - The Game of Global Domination (USA).cue`
(the .cue with both tracks: track 2 is the CD audio).

- Keyboard and gamepads work at once. F2 rebinds controls (`%APPDATA%\RiskDecomp\controls.json`).
  Default keyboard: arrows / WASD = D-pad, X or Space = Cross, C = Circle, Z = Square,
  V = Triangle, Q / E = L1 / R1, 1 / 3 = L2 / R2, Enter = Start, Tab / Right Shift = Select.
  A second gamepad becomes the controller in port 2.
- P opens the settings: volume, window mode, gamma, VSync, sharp or smooth picture and the FPS
  counter. F1 shows the debug overlay, F3 the whole video memory. F11 or Alt+Enter toggles
  borderless fullscreen.
- The memory card in slot 1 is `rust/memcard/slot1.mcd` (a standard 128 KiB raw card image that
  other emulators can read; override with `RISK_MEMCARD`). `RISK_MEMCARD2` inserts a card in slot 2.
- `rust/risk_trace.log` (written every 5 s) is the diagnostics log: frame pacing, interrupts,
  CD-ROM / SPU / pad / memory card activity, GPU state and command counts, and the game's own
  `printf` output. `rust/risk_vram.bin` is a video memory snapshot (1024x512, 16-bit) taken at the
  same time. If something goes wrong, send both.

## Rebuilding from the disc

You need Python 3, Ghidra 12.1, ghidra-cli 0.2 and a Rust toolchain. The work folder
(`..\Risk`, next to this repository) holds the extracted disc, the Ghidra project and the raw export.

```bat
set BIN=%USERPROFILE%\Downloads\Emus\PS1\Risk - The Game of Global Domination (USA)\Risk - The Game of Global Domination (USA)\Risk - The Game of Global Domination (USA) (Track 1).bin
cd tools
python psx_extract.py "%BIN%" ..\..\Risk\extracted
python psx2elf.py ..\..\Risk\extracted\files\SLUS_006.16 ..\..\Risk\extracted\SLUS_006.16.elf
python find_stubs.py ..\..\Risk\extracted\files\SLUS_006.16 ..\..\Risk\extracted\symbols.csv
set GHIDRA_CLI_READ_TIMEOUT=0
set W=D:/Development/Decomps/Risk
ghidra import %W%/extracted/SLUS_006.16.elf --projects-dir %W%/ghidra --project RISK --no-analyze
set G=ghidra --projects-dir %W%/ghidra --project RISK --program SLUS_006.16.elf
%G% script run SetGp.java -- 0x800A2C80
%G% script run ApplySymbols.java -- %W%/extracted/symbols.csv
%G% analyze
%G% script run FixNoReturn.java
%G% script run CreateGapFunctions.java -- 0x8001648C 0x8007ED60
%G% script run ExportPcode.java -- %W%/export
%G% script run ExportSheets.java -- %W%/export
python build_sheets.py && python resolve_hle.py && python gen_rust.py
```

(`ghidra import` finishes in seconds but the CLI may not return; check `ghidra status`.)

## The executable

`SLUS_006.16` is a PS-X EXE of 0x94800 bytes loaded at 0x80010000, entry `__start` 0x80061F9C,
gp 0x800A2C80, BSS 0x800A4120..0x801084A0, heap above it up to the stack at the top of the 2 MiB.
It was linked with PsyQ 4.x: Hasbro Interactive's game code comes first (0x8001648C..0x80061F9C),
then the startup code and the Sony libraries. It has no symbols; the 64 BIOS call stubs are named
from the kernel's function tables, a few library functions by hand (`sheets/manual_names.csv`,
with the evidence), and library code is assigned to libraries (libcd, libgpu, libspu, libpress,
libtap, libmcrd, libetc, libapi, libc, libgte) by the hardware it touches.

## Sheets

| Sheet | Key | Contents |
|---|---|---|
| `meta.csv` | `key` | Game ID, executable, entry point, gp, sizes and hash, SYSTEM.CNF, toolchain |
| `functions.csv` | `addr` | name, size, module (game / psyq), **unit, status, owner**, fan-in/out, signature, C path, notes |
| `units.csv` | `unit` | Work partitions: `game/seg_XXXXXXXX` (8 KiB address ranges of game code) and `psyq/<library>`, with status roll-ups |
| `manual_names.csv` | `addr` | Names identified by hand, with the evidence (always applied by build_sheets.py) |
| `symbols.csv` | `addr` | BIOS call stubs (table, function number) and `__start` |
| `hle.csv` | `name` | Functions replaced by high-level emulation in the Rust runtime |
| `calls.csv` | `caller,callee` | Static call graph |
| `instructions.csv` | `addr` | Every instruction (106,625): owning function, bytes, disassembly, **delay-slot flag**, **raw p-code semantics** |
| `memory.csv` | `addr` | Every byte of the executable image, 64 bytes/row hex |
| `registers.csv` | `name` | Ghidra's MIPS register layout (offsets used by p-code `R` varnodes) |
| `strings.csv` | `addr` | Defined strings + referencing functions |
| `globals.csv` | `addr` | Data labels, types, sizes, xref counts |
| `sections.csv` | `name` | Memory blocks (.kernel, .text, .bss, .scratch, .io) |
| `disc_files.csv` | `path` | Every file on the disc with LBA, size and form |

`instructions.csv`, `memory.csv`, `registers.csv` and `meta.csv` fully describe the program, and
they are what `gen_rust.py` consumes. P-code varnodes are written `<space><hexoffset>:<size>`,
where the space is `R` register, `U` temporary, `C` constant or `M` RAM. A MIPS branch's p-code
already contains its delay slot (Ghidra inlines it); delay-slot rows are flagged and only emitted
on their own when code jumps straight into one.

### Status lifecycle (`functions.csv:status`)
`raw` (auto name `FUN_…`) → `named` → `typed` → `clean` → `verified`.
To see what is left, read the per-status columns in `units.csv`.

## Rust / Bevy (`rust/`)

| Crate | What |
|---|---|
| `psx-core` | Stable ABI for generated code: R3000A context (compact register file), p-code ops with R3000A division semantics, inline RAM/scratchpad access, and the `Host` function table |
| `psx-runtime` | The PlayStation behind `Host`: interrupt controller, DMA, root counters, GPU (software rasterizer on 1 MiB VRAM), SPU (24 ADPCM voices, ADSR, reverb, CD input), CD-ROM controller (cue/bin, XA-ADPCM, CD-DA), MDEC, GTE, controller port, and the HLE BIOS kernel (A0h/B0h/C0h tables, events, interrupt chains and exit hook, heap, memory card file system) |
| `recomp/part_00..07` | **Generated.** One `pub fn f_<ADDR>(c, entry)` per function, from `instructions.csv`, with one match arm per basic block. Loop back-edges poll for interrupts |
| `risk-recomp` | Dispatch table, executable image (`mem/text.bin`), boot |
| `risk-bevy` | Bevy 0.19 app: runs the game, shows its display area on a quad under a 3D orthographic camera, plays the SPU output and feeds keyboard / gamepad input into the controller ports |

### How the console is reproduced

- **CPU**: static recompilation of every instruction's p-code. Calls to the BIOS (`jr t2` to
  0xA0/0xB0/0xC0) go to the HLE kernel. `syscall` implements Enter/ExitCriticalSection.
- **Time**: device time is host time in CPU cycles (33.8688 MHz). Vertical blank at the NTSC rate
  (263 lines of 2152 cycles), root counters, CD sector timing (75/150 sectors per second), SPU
  output (44100 Hz) all follow it, so the game runs at the console's speed.
- **Interrupts**: as the BIOS does it: the queued handler chains (SysEnqIntRP) run first, then root
  counter events, then the game's exit hook (libetc's dispatcher, installed with HookEntryInt and a
  setjmp buffer) runs on its own stack; its ReturnFromException unwinds back and the interrupted
  state is restored.
- **Controllers**: the game's libtap driver bit-bangs SIO0 itself; a digital pad answers on each
  connected port, with the /ACK interrupt timed by register accesses so the driver's bounded
  polling sees it exactly as on hardware.
- **HLE functions** (`sheets/hle.csv`): libetc's `v_wait` and `VSync(-1)`, libpress's
  `MDEC_in_sync` / `MDEC_out_sync`, libcd's `StGetNext` and the movie player's frame wait. Their
  timeouts count loop iterations; on a fast host they would expire at once, so they are given the
  console's real-time equivalent.

## Tests

`cargo test -p psx-runtime -p risk-recomp --release` (with the disc image at `RISK_DISC` or the
default location; tests that need it skip without it) checks the hardware models without running
the game: the STR movie decoder against an independent reference bitstream decoder, the game's own
recompiled `DecDCTvlc` against that reference, CD-ROM sector delivery the way libcd's `CdRead`
drives it, and sub-word stores to the DMA interrupt register.
