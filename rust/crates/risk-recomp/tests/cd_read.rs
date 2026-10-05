//! Drives the CD-ROM model the way libcd's CdRead does (2340-byte mode: acknowledge INT1, reset
//! and load the data FIFO, check the 3-word header) and checks that every sector arrives in order
//! starting at the Setloc target, also when the game acknowledges late.

use psx_runtime::{cdrom, machine};
use std::time::{Duration, Instant};

fn bcd(v: u32) -> u8 {
    ((v / 10) << 4 | (v % 10)) as u8
}

fn wait_irq(timeout_ms: u64) -> u8 {
    let t = Instant::now();
    loop {
        let m = machine();
        let now = m.now();
        cdrom::update(m, now);
        cdrom::write(m, 0x1F80_1800, 1);
        let f = cdrom::read(m, 0x1F80_1803, 1) as u8 & 7;
        if f != 0 {
            return f;
        }
        assert!(t.elapsed() < Duration::from_millis(timeout_ms), "no CD interrupt");
        std::thread::sleep(Duration::from_micros(200));
    }
}

fn ack() {
    let m = machine();
    cdrom::write(m, 0x1F80_1800, 1);
    cdrom::write(m, 0x1F80_1803, 0x07);
}

fn command(cmd: u8, params: &[u8]) {
    let m = machine();
    cdrom::write(m, 0x1F80_1800, 0);
    for p in params {
        cdrom::write(m, 0x1F80_1802, *p);
    }
    cdrom::write(m, 0x1F80_1801, cmd);
    assert_eq!(wait_irq(2000), 3, "command {cmd:02x} acknowledged");
    ack();
}

#[test]
fn cd_read_sequence_in_order() {
    let (_c, _shared) = risk_recomp::boot();
    let lba = 22u32 + 150; // a data sector near the start, as an absolute MSF position
    command(0x0E, &[0xA0]); // Setmode: double speed, 2340-byte sectors
    command(0x02, &[bcd(lba / 4500), bcd(lba / 75 % 60), bcd(lba % 75)]);
    command(0x06, &[]); // ReadN
    for i in 0..12u32 {
        assert_eq!(wait_irq(2000), 1, "data INT1");
        if i % 3 == 1 {
            // The game is late: the next sector is due before this one is acknowledged.
            std::thread::sleep(Duration::from_millis(9));
        }
        ack();
        let m = machine();
        cdrom::write(m, 0x1F80_1800, 0);
        cdrom::write(m, 0x1F80_1803, 0x00);
        cdrom::write(m, 0x1F80_1803, 0x80);
        let hdr = cdrom::dma_read(m).to_le_bytes();
        let from_bcd = |b: u8| (b >> 4) as u32 * 10 + (b & 0xF) as u32;
        let got = (from_bcd(hdr[0]) * 60 + from_bcd(hdr[1])) * 75 + from_bcd(hdr[2]);
        assert_eq!(got, lba + i, "sector {i} in order");
    }
}
