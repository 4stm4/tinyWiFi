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
    geometry::Angle,
    mono_font::{
        ascii::{FONT_6X10, FONT_7X13_BOLD, FONT_9X18_BOLD, FONT_10X20},
        MonoTextStyle,
    },
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{Arc, Circle, Ellipse, Line, PrimitiveStyle, Rectangle},
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

// ── Drawing helpers ───────────────────────────────────────────────────────────

// Draw text with 2×3 offset grid for extra-bold appearance.
fn xbold(buf: &mut Buf, text: &str, x: i32, y: i32, style: MonoTextStyle<BinaryColor>) {
    for (dx, dy) in [(0, 0), (1, 0), (2, 0), (0, 1), (1, 1), (2, 1)] {
        Text::with_baseline(text, Point::new(x + dx, y + dy), style, Baseline::Top)
            .draw(buf)
            .ok();
    }
}

fn sep(buf: &mut Buf, y: i32) {
    let st = PrimitiveStyle::with_stroke(BinaryColor::On, 1);
    Line::new(Point::new(2, y), Point::new(W as i32 - 3, y))
        .into_styled(st)
        .draw(buf)
        .ok();
}

/// Circular progress gauge.
/// - background thin circle
/// - thick arc from 12 o'clock clockwise for `pct`%
/// - label ("RAM"/"CPU") and percentage centered inside
fn draw_gauge(buf: &mut Buf, cx: i32, cy: i32, r: u32, pct: u8, label: &str) {
    let thin = PrimitiveStyle::with_stroke(BinaryColor::On, 2);
    let thick = PrimitiveStyle::with_stroke(BinaryColor::On, 4);

    // Background circle
    Circle::with_center(Point::new(cx, cy), r * 2)
        .into_styled(thin)
        .draw(buf)
        .ok();

    // Progress arc (clockwise from 12 o'clock; in e-g coords 270°=-90° is up on screen,
    // positive sweep is clockwise on screen because Y-axis is inverted).
    if pct > 0 {
        let sweep = pct as f32 / 100.0 * 360.0;
        Arc::new(
            Point::new(cx - r as i32, cy - r as i32),
            r * 2,
            Angle::from_degrees(-90.0),
            Angle::from_degrees(sweep),
        )
        .into_styled(thick)
        .draw(buf)
        .ok();
    }

    // Label ("RAM" / "CPU") — FONT_6X10, centered above middle
    let f_label = FONT_6X10;
    let lw = label.len() as i32 * f_label.character_size.width as i32;
    let label_style = MonoTextStyle::new(&f_label, BinaryColor::On);
    Text::with_baseline(
        label,
        Point::new(cx - lw / 2, cy - 12),
        label_style,
        Baseline::Top,
    )
    .draw(buf)
    .ok();

    // Percentage — FONT_7X13_BOLD, centered below label
    let pct_str = format!("{pct}%");
    let pw = pct_str.len() as i32 * FONT_7X13_BOLD.character_size.width as i32;
    let pct_style = MonoTextStyle::new(&FONT_7X13_BOLD, BinaryColor::On);
    Text::with_baseline(
        &pct_str,
        Point::new(cx - pw / 2, cy),
        pct_style,
        Baseline::Top,
    )
    .draw(buf)
    .ok();
}

/// Two-person silhouette at (x, y) top-left, ~18×18 area.
fn draw_icon_people(buf: &mut Buf, x: i32, y: i32) {
    let st = PrimitiveStyle::with_stroke(BinaryColor::On, 1);
    // back person (right, higher)
    Circle::with_center(Point::new(x + 12, y + 4), 6).into_styled(st).draw(buf).ok();
    Circle::with_center(Point::new(x + 12, y + 13), 10).into_styled(st).draw(buf).ok();
    // front person (left, lower)
    Circle::with_center(Point::new(x + 7, y + 6), 6).into_styled(st).draw(buf).ok();
    Circle::with_center(Point::new(x + 7, y + 15), 10).into_styled(st).draw(buf).ok();
}

/// Globe icon at (x, y) top-left, ~18×18 area.
fn draw_icon_globe(buf: &mut Buf, x: i32, y: i32) {
    let st = PrimitiveStyle::with_stroke(BinaryColor::On, 1);
    let cx = x + 9;
    let cy = y + 9;
    // outer circle
    Circle::with_center(Point::new(cx, cy), 18).into_styled(st).draw(buf).ok();
    // equator
    Line::new(Point::new(cx - 9, cy), Point::new(cx + 9, cy))
        .into_styled(st).draw(buf).ok();
    // central meridian
    Line::new(Point::new(cx, cy - 9), Point::new(cx, cy + 9))
        .into_styled(st).draw(buf).ok();
    // inner longitude ellipse
    Ellipse::with_center(Point::new(cx, cy), Size::new(9, 18))
        .into_styled(st).draw(buf).ok();
}

/// Clock icon at (x, y) top-left, ~18×18 area.
fn draw_icon_clock(buf: &mut Buf, x: i32, y: i32) {
    let st  = PrimitiveStyle::with_stroke(BinaryColor::On, 1);
    let st2 = PrimitiveStyle::with_stroke(BinaryColor::On, 2);
    let cx = x + 9;
    let cy = y + 9;
    // outer circle
    Circle::with_center(Point::new(cx, cy), 18).into_styled(st).draw(buf).ok();
    // minute hand (12 o'clock)
    Line::new(Point::new(cx, cy), Point::new(cx, cy - 6))
        .into_styled(st2).draw(buf).ok();
    // hour hand (3 o'clock)
    Line::new(Point::new(cx, cy), Point::new(cx + 5, cy))
        .into_styled(st2).draw(buf).ok();
}

// ── Renderer impl ─────────────────────────────────────────────────────────────

impl Renderer for EpaperRenderer {
    fn is_available(&self) -> bool {
        Path::new("/dev/spidev0.0").exists()
    }

    fn render(&mut self, st: &DisplayStatus) -> io::Result<()> {
        self.buf.clear();

        let fill = PrimitiveStyle::with_fill(BinaryColor::On);

        // ── Title bar (0-44): white text on black ──────────────────────────
        Rectangle::new(Point::new(0, 0), Size::new(W, 44))
            .into_styled(fill)
            .draw(&mut self.buf).ok();

        let mut f_brand = FONT_7X13_BOLD;  f_brand.character_spacing = 4;
        let mut f_title = FONT_10X20;      f_title.character_spacing = 2;

        xbold(&mut self.buf, "4STM4",    4, 2,  MonoTextStyle::new(&f_brand, BinaryColor::Off));
        xbold(&mut self.buf, "TinyWifi", 3, 18, MonoTextStyle::new(&f_title, BinaryColor::Off));

        sep(&mut self.buf, 44);

        // ── IP row (45-72) ─────────────────────────────────────────────────
        let ip = st.ip.map(|a| a.to_string()).unwrap_or_else(|| "—".into());
        xbold(&mut self.buf, &ip, 3, 48, MonoTextStyle::new(&FONT_9X18_BOLD, BinaryColor::On));

        sep(&mut self.buf, 73);

        // ── Circular gauges (74-147): RAM left, CPU right ──────────────────
        // Gauge centers: left cx=32, right cx=92, cy=110, r=27
        let ram = st.ram_used_percent.unwrap_or(0);
        let cpu = st.cpu_used_percent.unwrap_or(0);
        draw_gauge(&mut self.buf, 32,  110, 27, ram, "RAM");
        draw_gauge(&mut self.buf, 92,  110, 27, cpu, "CPU");

        sep(&mut self.buf, 148);

        // ── Icon rows ──────────────────────────────────────────────────────
        let mut f_data = FONT_9X18_BOLD; f_data.character_spacing = 1;
        let data_s = MonoTextStyle::new(&f_data, BinaryColor::On);

        // clients (148-183, center y=165)
        draw_icon_people(&mut self.buf, 2, 157);
        let clients = format!("{} clients", st.clients);
        xbold(&mut self.buf, &clients, 22, 157, data_s);

        sep(&mut self.buf, 184);

        // WAN (184-213, center y=199)
        draw_icon_globe(&mut self.buf, 2, 191);
        let wan = if st.wan { "WAN: OK" } else { "WAN: NO" };
        xbold(&mut self.buf, wan, 22, 191, data_s);

        sep(&mut self.buf, 214);

        // uptime (214-249, center y=231)
        draw_icon_clock(&mut self.buf, 2, 223);
        let up = st.uptime_secs
            .map(|s| format!("Up {}", short_uptime(s)))
            .unwrap_or_else(|| "Up —".into());
        xbold(&mut self.buf, &up, 22, 223, data_s);

        self.flush()
    }
}
