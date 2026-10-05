//! Diagnostics for testers: a deduplicated log, event counters and a periodic trace written to
//! `risk_trace.log` in the working directory (every 5 s: frame pacing, interrupts, CD / SPU /
//! pad / memory card activity, the most frequent counted events and the latest log lines).

use crate::{machine, Machine, LAST_FN};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

struct LogState {
    lines: Vec<String>,
    seen: BTreeMap<String, u64>,
    counts: BTreeMap<String, u64>,
}

fn state() -> &'static Mutex<LogState> {
    static S: OnceLock<Mutex<LogState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(LogState { lines: Vec::new(), seen: BTreeMap::new(), counts: BTreeMap::new() }))
}

pub fn log(mut msg: String) {
    if msg.starts_with("unknown call target") || msg.starts_with("mid-block") {
        let f = LAST_FN.load(Relaxed);
        msg += &format!(" (last function {:#010x} {})", f, crate::function_name(f).unwrap_or("?"));
    }
    let mut s = state().lock().unwrap();
    let n = s.seen.entry(msg.clone()).or_default();
    *n += 1;
    if *n == 1 && s.lines.len() < 20_000 {
        eprintln!("[risk] {msg}");
        s.lines.push(msg);
    }
}

/// Count an event (printed in the trace instead of logging every occurrence).
pub fn count(what: &str) {
    let mut s = state().lock().unwrap();
    if let Some(n) = s.counts.get_mut(what) {
        *n += 1;
    } else {
        s.counts.insert(what.to_string(), 1);
    }
}

/// Last `n` log lines (for the on-screen overlay).
pub fn tail(n: usize) -> Vec<String> {
    let s = state().lock().unwrap();
    s.lines.iter().rev().take(n).rev().cloned().collect()
}

struct Trace {
    last: Instant,
    start: Instant,
    frames: u64,
    irqs: u64,
    fn_entries: u64,
    sectors: u64,
    gp0: [u64; 256],
    file: Option<std::fs::File>,
}

fn trace() -> &'static Mutex<Trace> {
    static T: OnceLock<Mutex<Trace>> = OnceLock::new();
    T.get_or_init(|| {
        let file = std::fs::File::create("risk_trace.log").ok();
        Mutex::new(Trace { last: Instant::now(), start: Instant::now(), frames: 0, irqs: 0, fn_entries: 0, sectors: 0, gp0: [0; 256], file })
    })
}

/// Called at every vertical blank; writes a trace block every 5 seconds.
pub fn tick(m: &mut Machine) {
    let mut t = trace().lock().unwrap();
    t.frames += 1;
    if t.last.elapsed().as_secs_f32() < 5.0 {
        return;
    }
    let dt = t.last.elapsed().as_secs_f32();
    t.last = Instant::now();
    let fe = psx_core::FN_ENTRIES.load(Relaxed);
    let irqs = m.kernel.irq_count;
    let sectors = m.cd.sectors_read;
    let last = LAST_FN.load(Relaxed);
    let mut out = format!(
        "=== t={:.0}s: {:.1} vblanks/s, {} interrupts ({} via the exit hook), {:.1}M fn entries/s, last fn {last:#010x} {}\n\
         gpu: {} prims, display {}x{} at ({},{}) {} | cd: {} sectors (+{}), mode {:02x}, xa {} sectors, cd audio queued {} | \
         spu: {} samples, audio queued {} (underruns {}) | pad polls {} | memcard ops {}\n\
         mdec: {} commands, {} words in, {} macroblocks, {} words out, {} queued | dma1 chcr {:08x} bcr {:08x}
         I_STAT {:03x} I_MASK {:03x} | io r/w {}/{} | calls {} unknown {} block misses {}\n",
        t.start.elapsed().as_secs_f32(),
        t.frames as f32 / dt,
        irqs - t.irqs,
        m.kernel.hook_count,
        (fe - t.fn_entries) as f32 / dt / 1e6,
        crate::function_name(last).unwrap_or("?"),
        m.gpu.prims,
        m.gpu.hres(),
        if m.gpu.interlaced() { 480 } else { 240 },
        m.gpu.display_x,
        m.gpu.display_y,
        if m.gpu.display_off { "(off)" } else { "" },
        sectors,
        sectors - t.sectors,
        m.cd.mode,
        m.cd.xa.sectors,
        m.cd.audio.len(),
        m.spu.samples_out,
        m.shared.audio.queued(),
        crate::audio::UNDERRUNS.load(Relaxed),
        m.sio.polls,
        m.kernel.card.ops,
        m.mdec.commands,
        m.mdec.words_in,
        m.mdec.macroblocks,
        m.mdec.words_out,
        m.mdec.out_available(),
        m.dma.ch[1].chcr,
        m.dma.ch[1].bcr,
        m.istat,
        m.imask,
        crate::bus::IO_READS.load(Relaxed),
        crate::bus::IO_WRITES.load(Relaxed),
        psx_core::CALLS.load(Relaxed),
        psx_core::UNKNOWN_TARGETS.load(Relaxed),
        psx_core::BLOCK_MISSES.load(Relaxed),
    );
    // GPU drawing state, the GP0 commands of this interval and a VRAM snapshot (risk_vram.bin,
    // 1024x512 16-bit little-endian) for diagnosing rendering problems.
    {
        let g = &m.gpu;
        let e = &g.env;
        out += &format!(
            "  gpu: display ({},{}) h {:#x}-{:#x} v {:#x}-{:#x} mode {:#04x}{} flips {} | draw area ({},{})-({},{}) offset ({},{}) texpage {:#06x} window {}/{}/{}/{} mask set {} check {}
",
            g.display_x, g.display_y, g.h_start, g.h_end, g.v_start, g.v_end, g.mode,
            if g.display_off { " (off)" } else { "" }, g.flips,
            e.area_x1, e.area_y1, e.area_x2, e.area_y2, e.off_x, e.off_y, e.texpage,
            e.tw_mask_x, e.tw_mask_y, e.tw_off_x, e.tw_off_y, e.set_mask, e.check_mask,
        );
        let mut cmds: Vec<(usize, u64)> =
            (0..256).map(|i| (i, g.cmd_counts[i] - t.gp0[i])).filter(|c| c.1 > 0).collect();
        cmds.sort_by(|a, b| b.1.cmp(&a.1));
        let list: Vec<String> = cmds.iter().take(20).map(|(c, n)| format!("{c:02x}:{n}")).collect();
        out += &format!("  gp0 commands: {}
", list.join(" "));
        t.gp0 = g.cmd_counts;
        let bytes: Vec<u8> = g.vram.iter().flat_map(|v| v.to_le_bytes()).collect();
        let _ = std::fs::write("risk_vram.bin", bytes);
    }
    t.frames = 0;
    t.irqs = irqs;
    t.fn_entries = fe;
    t.sectors = sectors;
    {
        let s = state().lock().unwrap();
        let mut counts: Vec<_> = s.counts.iter().collect();
        counts.sort_by(|a, b| b.1.cmp(a.1));
        for (k, v) in counts.iter().take(16) {
            out += &format!("  {v:>9} x {k}\n");
        }
        for l in s.lines.iter().rev().take(12).rev() {
            out += &format!("  > {l}\n");
        }
    }
    if let Some(f) = t.file.as_mut() {
        let _ = f.write_all(out.as_bytes());
        let _ = f.flush();
    }
    let _ = machine;
}
