//! Decodes the logo movie's frames with an independent reference bitstream (v2/v3) decoder and
//! checks that the MDEC model turns each one into the full set of macroblocks.

use super::mdec::Mdec;
#[path = "strref.rs"]
mod strref;
use strref::{frames, vlc};

/// Feed run-length halfwords (header pair first) to a fresh MDEC as a 15-bit decode command.
pub(crate) fn mdec_macroblocks(codes: &[u16]) -> u64 {
    let rl = codes[0] as u32;
    let mut m = Mdec::new();
    m.test_write(((codes[1] as u32) << 16 | rl) | 0x0800_0000 | 0x0200_0000);
    let mut words: Vec<u32> =
        codes[2..].chunks(2).map(|c| c[0] as u32 | (*c.get(1).unwrap_or(&0xFE00) as u32) << 16).collect();
    words.resize(rl as usize, 0xFE00_FE00);
    for w in &words {
        m.test_write(*w);
    }
    m.macroblocks
}

#[test]
fn logo_movie_frames_decode_fully() {
    let fs = frames(173528, 2256);
    if fs.is_empty() {
        eprintln!("disc image not found; skipped");
        return;
    }
    for (i, f) in fs.iter().enumerate().take(60) {
        let (codes, blocks) = vlc(f);
        let mb = mdec_macroblocks(&codes);
        eprintln!(
            "frame {}: {} blocks, {} code words (rl {}), {} macroblocks",
            i + 1,
            blocks,
            (codes.len() - 2 + 1) / 2,
            codes[0],
            mb
        );
        assert_eq!(blocks, 1800, "frame {} bitstream", i + 1);
        assert_eq!(mb, 300, "frame {} mdec", i + 1);
    }
}
