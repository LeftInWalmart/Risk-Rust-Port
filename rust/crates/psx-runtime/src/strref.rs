//! Reference STR (v2/v3) bitstream decoder and frame reader, shared by the decoder tests.

/// Track 1 of the disc image: next to `RISK_DISC` (the .cue), or in the default location.
fn bin_path() -> std::path::PathBuf {
    let name = "Risk - The Game of Global Domination (USA)";
    let cue = std::env::var("RISK_DISC").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
        std::path::Path::new(&home).join(format!("Downloads/Emus/PS1/{name}/{name}/{name}.cue"))
    });
    cue.with_file_name(format!("{name} (Track 1).bin"))
}

struct Bits<'a> {
    d: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn bit(&self, i: usize) -> u32 {
        let w = i / 16;
        if 2 * w + 1 >= self.d.len() {
            return 0;
        }
        let v = u16::from_le_bytes([self.d[2 * w], self.d[2 * w + 1]]) as u32;
        (v >> (15 - i % 16)) & 1
    }
    fn peek(&self, n: usize) -> u32 {
        (0..n).fold(0, |a, i| (a << 1) | self.bit(self.pos + i))
    }
    fn get(&mut self, n: usize) -> u32 {
        let v = self.peek(n);
        self.pos += n;
        v
    }
}

// MPEG-1 dct_coeff_next (run, level) codes without the sign bit.
const AC: &[(&str, u32, i32)] = &[
    ("11", 0, 1), ("011", 1, 1), ("0100", 0, 2), ("0101", 2, 1), ("00101", 0, 3), ("00111", 3, 1),
    ("00110", 4, 1), ("000110", 1, 2), ("000111", 5, 1), ("000101", 6, 1), ("000100", 7, 1),
    ("0000110", 0, 4), ("0000100", 2, 2), ("0000111", 8, 1), ("0000101", 9, 1),
    ("00100110", 0, 5), ("00100001", 0, 6), ("00100101", 1, 3), ("00100100", 3, 2), ("00100111", 10, 1),
    ("00100011", 11, 1), ("00100010", 12, 1), ("00100000", 13, 1),
    ("0000001010", 0, 7), ("0000001100", 1, 4), ("0000001011", 2, 3), ("0000001111", 4, 2),
    ("0000001001", 5, 2), ("0000001110", 14, 1), ("0000001101", 15, 1), ("0000001000", 16, 1),
    ("000000011101", 0, 8), ("000000011000", 0, 9), ("000000010011", 0, 10), ("000000010000", 0, 11),
    ("000000011011", 1, 5), ("000000010100", 2, 4), ("000000011100", 3, 3), ("000000010010", 4, 3),
    ("000000011110", 6, 2), ("000000010101", 7, 2), ("000000010001", 8, 2), ("000000011111", 17, 1),
    ("000000011010", 18, 1), ("000000011001", 19, 1), ("000000010111", 20, 1), ("000000010110", 21, 1),
    ("0000000011010", 0, 12), ("0000000011001", 0, 13), ("0000000011000", 0, 14), ("0000000010111", 0, 15),
    ("0000000010110", 1, 6), ("0000000010101", 1, 7), ("0000000010100", 2, 5), ("0000000010011", 3, 4),
    ("0000000010010", 5, 3), ("0000000010001", 9, 2), ("0000000010000", 10, 2), ("0000000011111", 22, 1),
    ("0000000011110", 23, 1), ("0000000011101", 24, 1), ("0000000011100", 25, 1), ("0000000011011", 26, 1),
    ("00000000011111", 0, 16), ("00000000011110", 0, 17), ("00000000011101", 0, 18), ("00000000011100", 0, 19),
    ("00000000011011", 0, 20), ("00000000011010", 0, 21), ("00000000011001", 0, 22), ("00000000011000", 0, 23),
    ("00000000010111", 0, 24), ("00000000010110", 0, 25), ("00000000010101", 0, 26), ("00000000010100", 0, 27),
    ("00000000010011", 0, 28), ("00000000010010", 0, 29), ("00000000010001", 0, 30), ("00000000010000", 0, 31),
    ("000000000011000", 0, 32), ("000000000010111", 0, 33), ("000000000010110", 0, 34), ("000000000010101", 0, 35),
    ("000000000010100", 0, 36), ("000000000010011", 0, 37), ("000000000010010", 0, 38), ("000000000010001", 0, 39),
    ("000000000010000", 0, 40), ("000000000011111", 1, 8), ("000000000011110", 1, 9), ("000000000011101", 1, 10),
    ("000000000011100", 1, 11), ("000000000011011", 1, 12), ("000000000011010", 1, 13), ("000000000011001", 1, 14),
    ("0000000000010011", 1, 15), ("0000000000010010", 1, 16), ("0000000000010001", 1, 17), ("0000000000010000", 1, 18),
    ("0000000000010100", 6, 3), ("0000000000011010", 11, 2), ("0000000000011001", 12, 2), ("0000000000011000", 13, 2),
    ("0000000000010111", 14, 2), ("0000000000010110", 15, 2), ("0000000000010101", 16, 2), ("0000000000011111", 27, 1),
    ("0000000000011110", 28, 1), ("0000000000011101", 29, 1), ("0000000000011100", 30, 1), ("0000000000011011", 31, 1),
];
const DC_Y: [&str; 9] = ["100", "00", "01", "101", "110", "1110", "11110", "111110", "1111110"];
const DC_C: [&str; 9] = ["00", "01", "10", "110", "1110", "11110", "111110", "1111110", "11111110"];

fn matches(b: &Bits, code: &str) -> bool {
    b.peek(code.len()) == u32::from_str_radix(code, 2).unwrap()
}

/// Bitstream -> MDEC run-length halfwords (header pair first), as libpress's DecDCTvlc does.
pub fn vlc(frame: &[u8]) -> (Vec<u16>, usize) {
    let rl = u16::from_le_bytes([frame[0], frame[1]]);
    let q = u16::from_le_bytes([frame[4], frame[5]]) as u32;
    let ver = u16::from_le_bytes([frame[6], frame[7]]);
    let mut b = Bits { d: &frame[8..], pos: 0 };
    let mut out = vec![rl, 0x3800];
    let mut pred = [0i32; 3];
    let mut blocks = 0usize;
    loop {
        let comp = match blocks % 6 {
            0 => 0,
            1 => 1,
            _ => 2,
        };
        if ver >= 3 {
            if b.peek(10) == 0x3FF {
                break;
            }
            let tab = if comp < 2 { &DC_C } else { &DC_Y };
            let Some(size) = tab.iter().position(|c| matches(&b, c)) else { break };
            b.pos += tab[size].len();
            let mut diff = 0i32;
            if size > 0 {
                let v = b.get(size) as i32;
                diff = if v >> (size - 1) == 0 { v - ((1 << size) - 1) } else { v };
            }
            pred[comp] += diff;
            out.push(((q << 10) | (((pred[comp] as u32) << 2) & 0x3FF)) as u16);
        } else {
            if b.peek(10) == 0x1FF {
                break;
            }
            out.push(((q << 10) | b.get(10)) as u16);
        }
        loop {
            if matches(&b, "10") {
                b.pos += 2;
                out.push(0xFE00);
                break;
            }
            if matches(&b, "000001") {
                b.pos += 6;
                out.push(b.get(16) as u16);
                continue;
            }
            let Some(&(code, run, lvl)) = AC.iter().find(|(c, _, _)| matches(&b, c)) else {
                panic!("bad ac code at bit {} (block {blocks})", b.pos)
            };
            b.pos += code.len();
            let lvl = if b.get(1) != 0 { -lvl } else { lvl };
            out.push(((run << 10) | (lvl as u32 & 0x3FF)) as u16);
        }
        blocks += 1;
    }
    for _ in 0..=0x40 {
        out.push(0xFE00);
    }
    (out, blocks)
}

pub fn frames(lba: u64, sectors: u64) -> Vec<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(bin_path()) else { return Vec::new() };
    let mut parts: std::collections::BTreeMap<u32, Vec<(u16, Vec<u8>)>> = Default::default();
    let mut s = vec![0u8; 2352];
    for i in 0..sectors {
        f.seek(SeekFrom::Start((lba + i) * 2352)).unwrap();
        f.read_exact(&mut s).unwrap();
        let d = &s[24..24 + 2048];
        if s[18] & 4 != 0 || u32::from_le_bytes(d[0..4].try_into().unwrap()) != 0x8001_0160 {
            continue;
        }
        let chunk = u16::from_le_bytes([d[4], d[5]]);
        let frame = u32::from_le_bytes(d[8..12].try_into().unwrap());
        parts.entry(frame).or_default().push((chunk, d[32..].to_vec()));
    }
    parts
        .into_values()
        .map(|mut v| {
            v.sort_by_key(|p| p.0);
            v.into_iter().flat_map(|p| p.1).collect()
        })
        .collect()
}

