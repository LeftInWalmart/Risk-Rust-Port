//! Runs the game's own (recompiled) DecDCTvlc on the logo movie's frames and compares its output
//! with the independent reference decoder, then feeds it to the MDEC model.

#[path = "../../psx-runtime/src/strref.rs"]
mod strref;

use psx_runtime::{machine, mdec};

const DEC_DCT_VLC: u32 = 0x8007_B148;
const SRC: u32 = 0x8010_0000;
const DST: u32 = 0x8014_0000;

#[test]
fn game_vlc_matches_reference() {
    let fs = strref::frames(173528, 2256);
    if fs.is_empty() {
        eprintln!("disc image not found; skipped");
        return;
    }
    let (mut c, _shared) = risk_recomp::boot();
    let mut bad = 0;
    for (i, f) in fs.iter().enumerate().take(60) {
        let (want, _) = strref::vlc(f);
        let m = machine();
        let s = (SRC & 0x1F_FFFF) as usize;
        m.ram[s..s + f.len()].copy_from_slice(f);
        let d = (DST & 0x1F_FFFF) as usize;
        m.ram[d..d + 0x20000].fill(0xAA);
        let v0 = c.call_guest(DEC_DCT_VLC, &[SRC, DST]);
        let got: Vec<u16> = (0..want.len()).map(|k| u16::from_le_bytes([m.ram[d + 2 * k], m.ram[d + 2 * k + 1]])).collect();
        let first = got.iter().zip(&want).position(|(a, b)| a != b);
        // MDEC: 15-bit decode of the game's output.
        mdec::write_control(m, 0x8000_0000);
        let before = m.mdec.macroblocks;
        let rl = got[0] as u32;
        mdec::write_command(m, ((got[1] as u32) << 16 | rl) | 0x0800_0000 | 0x0200_0000);
        for k in 0..rl as usize {
            let w = u32::from_le_bytes(m.ram[d + 4 + 4 * k..d + 8 + 4 * k].try_into().unwrap());
            mdec::write_command(m, w);
        }
        let mb = m.mdec.macroblocks - before;
        eprintln!("frame {}: v0 {v0}, first mismatch {:?}, {} macroblocks", i + 1, first, mb);
        if let Some(p) = first {
            bad += 1;
            let lo = p.saturating_sub(4);
            eprintln!("  want {:04x?}\n  got  {:04x?}", &want[lo..(p + 6).min(want.len())], &got[lo..(p + 6).min(got.len())]);
        }
    }
    assert_eq!(bad, 0);
}

/// libcd's stream reader arms / disarms the CD-DMA completion interrupt with a byte store to
/// DICR+2; that must change only channel 3's enable bit and acknowledge nothing.
#[test]
fn dicr_byte_store() {
    let (mut c, _shared) = risk_recomp::boot();
    let m = machine();
    psx_runtime::bus::io_write(&mut c, 0x1F80_10F4, 4, 0x0082_0000); // master + ch1 enable
    m.dma.dicr |= 0x0200_0000; // ch1 flag pending
    psx_runtime::bus::io_write(&mut c, 0x1F80_10F6, 1, 0x82 | 0x08);
    assert_eq!(m.dma.dicr, 0x028A_0000, "ch3 enabled, ch1 kept, flag kept");
    psx_runtime::bus::io_write(&mut c, 0x1F80_10F6, 1, 0x82);
    assert_eq!(m.dma.dicr, 0x0282_0000, "ch3 disabled");
}
