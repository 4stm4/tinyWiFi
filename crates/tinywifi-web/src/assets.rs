//! Static assets baked into the binary: the Nervum design-system stylesheet
//! and the brand/UI/mono web fonts. Embedding them keeps the panel a single
//! self-contained binary that serves correctly on an offline device — no
//! external CDN, no files to deploy alongside it.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

const STYLE_CSS: &str = include_str!("../assets/style.css");

const AUDIOWIDE_LATIN: &[u8] = include_bytes!("../assets/fonts/audiowide-latin.woff2");
const AUDIOWIDE_LATIN_EXT: &[u8] = include_bytes!("../assets/fonts/audiowide-latin-ext.woff2");
const SPACE_GROTESK: &[u8] = include_bytes!("../assets/fonts/space-grotesk.woff2");
const JETBRAINS_MONO: &[u8] = include_bytes!("../assets/fonts/jetbrains-mono.woff2");

/// Cache for a day: the stylesheet ships with the binary, so a new build is the
/// only thing that changes it.
const CSS_CACHE: &str = "public, max-age=86400";
/// Fonts never change for a given filename; cache them aggressively.
const FONT_CACHE: &str = "public, max-age=31536000, immutable";

pub async fn style_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, CSS_CACHE),
        ],
        STYLE_CSS,
    )
}

/// Serve one of the embedded woff2 faces by filename (`/fonts/:name`).
pub async fn font(Path(name): Path<String>) -> Response {
    let bytes: &'static [u8] = match name.as_str() {
        "audiowide-latin.woff2" => AUDIOWIDE_LATIN,
        "audiowide-latin-ext.woff2" => AUDIOWIDE_LATIN_EXT,
        "space-grotesk.woff2" => SPACE_GROTESK,
        "jetbrains-mono.woff2" => JETBRAINS_MONO,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, FONT_CACHE),
        ],
        bytes,
    )
        .into_response()
}
