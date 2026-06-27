//! Waveshare 2.13" V3 (SSD1675B) driver for Pi Zero 2W.
//!
//! SPI via /dev/spidev0.0, GPIO via /sys/class/gpio.
//! Requires in config.txt: dtparam=spi=on
//!
//! Pinout (pwnagotchi default):
//!   MOSI=GPIO10  CLK=GPIO11  CS=GPIO8(CE0)
//!   DC=GPIO25  RST=GPIO17  BUSY=GPIO24

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::BinaryColor,
    prelude::*,
    text::{Baseline, Text},
};
use spidev::{SpiModeFlags, Spidev, SpidevOptions};

use crate::render::Renderer;

// Native portrait dimensions: 128 × 250 (122 visible columns, 250 rows)
const W: u32 = 128;
const H: u32 = 250;
const ROW: usize = (W / 8) as usize; // 16 bytes per row
const BUF: usize = ROW * H as usize;  // 4000 bytes total

const PIN_RST:  u32 = 17;
const PIN_DC:   u32 = 25;
const PIN_BUSY: u32 = 24;

// ── Sysfs GPIO ────────────────────────────────────────────────────────────────

struct Pin(u32);

impl Pin {
    fn open(n: u32, dir: &str) -> io::Result<Self> {
        let path = format!("/sys/class/gpio/gpio{n}");
        if !Path::new(&path).exists() {
            let _ = fs::write("/sys/class/gpio/export", n.to_string());
            thread::sleep(Duration::from_millis(50));
        }
        fs::write(format!("{path}/direction"), dir)?;
        Ok(Pin(n))
    }

    fn set(&self, v: bool) -> io::Result<()> {
        fs::write(
            format!("/sys/class/gpio/gpio{}/value", self.0),
            if v { "1" } else { "0" },
        )
    }

    fn get(&self) -> io::Result<bool> {
        Ok(fs::read_to_string(format!("/sys/class/gpio/gpio{}/value", self.0))?
            .trim() == "1")
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        let _ = fs::write("/sys/class/gpio/unexport", self.0.to_string());
    }
}

// ── Frame buffer (DrawTarget) ─────────────────────────────────────────────────

struct Buf([u8; BUF]);

impl Buf {
    fn new() -> Self { Self([0xFF; BUF]) }
    fn clear(&mut self) { self.0.fill(0xFF); }
}

impl OriginDimensions for Buf {
    fn size(&self) -> Size { Size::new(W, H) }
}

impl DrawTarget for Buf {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(pt, color) in pixels {
            let (x, y) = (pt.x, pt.y);
            if x < 0 || y < 0 || x >= W as i32 || y >= H as i32 {
                continue;
            }
            let byte = y as usize * ROW + x as usize / 8;
            let bit  = 7 - (x as usize % 8);
            if color == BinaryColor::On {
                self.0[byte] &= !(1u8 << bit); // black
            } else {
                self.0[byte] |= 1u8 << bit;    // white
            }
        }
        Ok(())
    }
}

// ── Waveshare 2.13" V3 (SSD1675B) ────────────────────────────────────────────

pub struct EpaperRenderer {
    spi:  Spidev,
    rst:  Pin,
    dc:   Pin,
    busy: Pin,
    buf:  Buf,
}

impl EpaperRenderer {
    pub fn open() -> io::Result<Self> {
        if !Path::new("/dev/spidev0.0").exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "/dev/spidev0.0 not found"));
        }

        let mut spi = Spidev::open("/dev/spidev0.0")?;
        spi.configure(
            &SpidevOptions::new()
                .bits_per_word(8)
                .max_speed_hz(4_000_000)
                .mode(SpiModeFlags::SPI_MODE_0)
                .build(),
        )?;

        let rst  = Pin::open(PIN_RST, "out")?;
        let dc   = Pin::open(PIN_DC, "out")?;
        let busy = Pin::open(PIN_BUSY, "in")?;

        let mut r = Self { spi, rst, dc, busy, buf: Buf::new() };
        r.init()?;
        Ok(r)
    }

    fn reset(&mut self) -> io::Result<()> {
        self.rst.set(true)?;  thread::sleep(Duration::from_millis(20));
        self.rst.set(false)?; thread::sleep(Duration::from_millis(2));
        self.rst.set(true)?;  thread::sleep(Duration::from_millis(20));
        Ok(())
    }

    fn wait_busy(&self) -> io::Result<()> {
        for _ in 0..500 {
            if !self.busy.get()? { return Ok(()); }
            thread::sleep(Duration::from_millis(10));
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "EPD busy timeout"))
    }

    fn cmd(&mut self, c: u8) -> io::Result<()> {
        self.dc.set(false)?;
        self.spi.write_all(&[c])
    }

    fn dat(&mut self, d: &[u8]) -> io::Result<()> {
        self.dc.set(true)?;
        self.spi.write_all(d)
    }

    fn init(&mut self) -> io::Result<()> {
        self.reset()?;
        self.wait_busy()?;

        self.cmd(0x12)?;                                    // SW reset
        self.wait_busy()?;

        self.cmd(0x01)?; self.dat(&[0xF9, 0x00, 0x00])?;  // Driver output: 250 lines
        self.cmd(0x11)?; self.dat(&[0x03])?;               // Data entry: X+,Y+
        self.cmd(0x44)?; self.dat(&[0x00, 0x0F])?;         // X window: bytes 0..15
        self.cmd(0x45)?; self.dat(&[0x00,0x00, 0xF9,0x00])?; // Y window: 0..249
        self.cmd(0x3C)?; self.dat(&[0x05])?;               // Border: HiZ
        self.cmd(0x21)?; self.dat(&[0x00, 0x80])?;         // Display update ctrl
        self.cmd(0x18)?; self.dat(&[0x80])?;               // Temp sensor: internal
        self.cmd(0x4E)?; self.dat(&[0x00])?;               // X counter = 0
        self.cmd(0x4F)?; self.dat(&[0x00, 0x00])?;         // Y counter = 0
        self.wait_busy()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.cmd(0x4E)?; self.dat(&[0x00])?;
        self.cmd(0x4F)?; self.dat(&[0x00, 0x00])?;
        self.cmd(0x24)?;
        let data = self.buf.0;
        self.dat(&data)?;
        self.cmd(0x22)?; self.dat(&[0xF7])?; // full update sequence
        self.cmd(0x20)?;                       // activate
        self.wait_busy()
    }
}

impl Renderer for EpaperRenderer {
    fn is_available(&self) -> bool {
        Path::new("/dev/spidev0.0").exists()
    }

    fn render(&mut self, frame: &str) -> io::Result<()> {
        self.buf.clear();

        let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
        let mut y = 2i32;
        for line in frame.lines() {
            Text::with_baseline(line, Point::new(2, y), style, Baseline::Top)
                .draw(&mut self.buf)
                .ok();
            y += 12;
        }

        self.flush()
    }
}
