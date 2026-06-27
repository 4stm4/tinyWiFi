//! Waveshare 2.13" V2/V3 e-paper renderer for Pi Zero 2W.
//!
//! Pinout (pwnagotchi default / Waveshare standard):
//!   SPI0 MOSI=GPIO10  CLK=GPIO11  CS=GPIO8(CE0)
//!   DC=GPIO25  RST=GPIO17  BUSY=GPIO24
//!
//! Requires SPI enabled in config.txt: dtparam=spi=on

use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;

use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::BinaryColor,
    prelude::*,
    text::{Baseline, Text},
};
use epd_waveshare::{
    epd2in13_v2::{Display2in13, Epd2in13},
    graphics::DisplayRotation,
    prelude::*,
};
use rppal::gpio::{Gpio, InputPin, OutputPin};
use rppal::spi::{Bus, Mode, SlaveSelect, Spi};

use crate::render::Renderer;

// Waveshare 2.13" / pwnagotchi standard pinout
const PIN_CS: u8   = 8;
const PIN_DC: u8   = 25;
const PIN_RST: u8  = 17;
const PIN_BUSY: u8 = 24;

// ── Delay shim ────────────────────────────────────────────────────────────────

struct HalDelay;

impl embedded_hal::blocking::delay::DelayMs<u8> for HalDelay {
    fn delay_ms(&mut self, ms: u8) {
        thread::sleep(Duration::from_millis(ms as u64));
    }
}

impl embedded_hal::blocking::delay::DelayMs<u16> for HalDelay {
    fn delay_ms(&mut self, ms: u16) {
        thread::sleep(Duration::from_millis(ms as u64));
    }
}

// ── Renderer ──────────────────────────────────────────────────────────────────

type Epd = Epd2in13<Spi, OutputPin, InputPin, OutputPin, OutputPin>;

pub struct EpaperRenderer {
    epd:     Epd,
    display: Display2in13,
    spi:     Spi,
    delay:   HalDelay,
}

impl EpaperRenderer {
    pub fn open() -> io::Result<Self> {
        if !Path::new("/dev/spidev0.0").exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "SPI not available"));
        }

        let mut spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, 4_000_000, Mode::Mode0)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SPI: {e}")))?;

        let gpio = Gpio::new()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("GPIO: {e}")))?;

        let cs   = gpio.get(PIN_CS).map_err(gpio_io)?.into_output();
        let dc   = gpio.get(PIN_DC).map_err(gpio_io)?.into_output();
        let rst  = gpio.get(PIN_RST).map_err(gpio_io)?.into_output();
        let busy = gpio.get(PIN_BUSY).map_err(gpio_io)?.into_input();

        let mut delay = HalDelay;

        let epd = Epd2in13::new(&mut spi, cs, busy, dc, rst, &mut delay)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("EPD init: {e:?}")))?;

        let mut display = Display2in13::default();
        display.set_rotation(DisplayRotation::Rotate90);

        Ok(Self { epd, display, spi, delay })
    }
}

fn gpio_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

fn epd_io<E: std::fmt::Debug>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{e:?}"))
}

impl Renderer for EpaperRenderer {
    fn is_available(&self) -> bool {
        Path::new("/dev/spidev0.0").exists()
    }

    fn render(&mut self, frame: &str) -> io::Result<()> {
        self.display.clear_buffer(Color::White);

        let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
        let mut y = 2i32;
        for line in frame.lines() {
            Text::with_baseline(line, Point::new(2, y), style, Baseline::Top)
                .draw(&mut self.display)
                .ok();
            y += 12;
        }

        self.epd
            .update_frame(&mut self.spi, self.display.buffer(), &mut self.delay)
            .map_err(epd_io)?;
        self.epd
            .display_frame(&mut self.spi, &mut self.delay)
            .map_err(epd_io)?;

        Ok(())
    }
}
