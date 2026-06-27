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
    mono_font::{ascii::{FONT_9X18_BOLD, FONT_10X20}, MonoTextStyle},
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{Line, PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};
use spidev::{SpiModeFlags, Spidev, SpidevOptions};

use crate::render::{short_uptime, Renderer};
use crate::status::DisplayStatus;

// Native portrait dimensions: 128 × 250 (122 visible columns, 250 rows)
const W: u32 = 128;
const H: u32 = 250;
const ROW: usize = (W / 8) as usize; // 16 bytes per row
const BUF: usize = ROW * H as usize;  // 4000 bytes total

// BCM GPIO numbers (hardware pin numbers per Raspberry Pi schematic)
const BCM_RST:  u32 = 17;
const BCM_DC:   u32 = 25;
const BCM_BUSY: u32 = 24;

// ── Sysfs GPIO ────────────────────────────────────────────────────────────────

// On Linux 5.x+ kernels the GPIO controller base is no longer guaranteed to be
// 0.  Pi kernel 6.x uses 512 (gpiochip512), so BCM pin N → sysfs pin 512+N.
// Read the base at runtime from /sys/class/gpio/gpiochip*/base.
fn gpio_base() -> u32 {
    let Ok(entries) = fs::read_dir("/sys/class/gpio") else { return 0 };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if s.starts_with("gpiochip") {
            let base_path = entry.path().join("base");
            if let Ok(v) = fs::read_to_string(&base_path) {
                if let Ok(n) = v.trim().parse::<u32>() {
                    // The chip that owns BCM GPIO 0-53 will have the highest base
                    // among chips with ngpio>=54; take the first match with ngpio>=54.
                    let ngpio_path = entry.path().join("ngpio");
                    if let Ok(ng) = fs::read_to_string(&ngpio_path) {
                        if let Ok(ng) = ng.trim().parse::<u32>() {
                            if ng >= 28 {
                                return n;
                            }
                        }
                    }
                }
            }
        }
    }
    0
}

struct Pin(u32);

impl Pin {
    fn open(bcm: u32, dir: &str) -> io::Result<Self> {
        let n = gpio_base() + bcm;
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

        let rst  = Pin::open(BCM_RST, "out")?;
        let dc   = Pin::open(BCM_DC, "out")?;
        let busy = Pin::open(BCM_BUSY, "in")?;

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

// Draw text three times with 1-px offsets to simulate extra-bold strokes.
fn xbold(buf: &mut Buf, text: &str, x: i32, y: i32, style: MonoTextStyle<BinaryColor>) {
    for (dx, dy) in [(0, 0), (1, 0), (2, 0), (0, 1), (1, 1), (2, 1)] {
        Text::with_baseline(text, Point::new(x + dx, y + dy), style, Baseline::Top)
            .draw(buf)
            .ok();
    }
}

impl Renderer for EpaperRenderer {
    fn is_available(&self) -> bool {
        Path::new("/dev/spidev0.0").exists()
    }

    fn render(&mut self, st: &DisplayStatus) -> io::Result<()> {
        self.buf.clear();

        let title_s = MonoTextStyle::new(&FONT_10X20, BinaryColor::Off);
        let bold    = MonoTextStyle::new(&FONT_9X18_BOLD, BinaryColor::On);
        let fill    = PrimitiveStyle::with_fill(BinaryColor::On);
        let stroke  = PrimitiveStyle::with_stroke(BinaryColor::On, 1);

        // Inverted title bar (30px)
        Rectangle::new(Point::new(0, 0), Size::new(W, 30))
            .into_styled(fill)
            .draw(&mut self.buf).ok();
        // Title also gets the xbold treatment (white-on-black, so Off color)
        let title_xb = MonoTextStyle::new(&FONT_10X20, BinaryColor::Off);
        xbold(&mut self.buf, "TinyWifi", 3, 5, title_xb);

        let ip      = st.ip.map(|a| a.to_string()).unwrap_or_else(|| "—".into());
        let ssid    = st.ssid.clone().unwrap_or_else(|| "—".into());
        let clients = format!("{} clients", st.clients);
        let wan     = if st.wan { "WAN: OK" } else { "WAN: NO" };
        let ram     = st.ram_used_percent.map(|p| format!("RAM {p}%")).unwrap_or_else(|| "RAM —".into());
        let up      = st.uptime_secs.map(|s| format!("Up  {}", short_uptime(s))).unwrap_or_else(|| "Up —".into());

        for (y, text) in [
            (34,  ip.as_str()),
            (68,  ssid.as_str()),
            (104, clients.as_str()),
            (138, wan),
            (174, ram.as_str()),
            (208, up.as_str()),
        ] {
            xbold(&mut self.buf, text, 3, y, bold);
        }

        for y in [96_i32, 166] {
            Line::new(Point::new(2, y), Point::new(W as i32 - 3, y))
                .into_styled(stroke)
                .draw(&mut self.buf).ok();
        }

        self.flush()
    }
}
