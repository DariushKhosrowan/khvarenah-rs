//! QR matrix rendering + minimal PNG encoding for share links (uses the
//! `qrcode` crate and `flate2` for zlib; no `image` crate dependency).

use crate::error::CFError;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

/// Render a QR code as a square of `u8` pixel values (0/255).
pub fn render_matrix(text: &str, scale: usize) -> Result<Vec<u8>, CFError> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| {
        CFError::new(
            "QR error",
            format!("Cannot generate QR: {e}"),
            "Input may be too long.",
        )
    })?;
    let width = code.width();
    let mut out = Vec::with_capacity(width * width * scale * scale);
    for y in 0..width {
        for _ in 0..scale {
            for x in 0..width {
                let dark = code[(x, y)] == qrcode::Color::Dark;
                for _ in 0..scale {
                    out.push(if dark { 0 } else { 255 });
                }
            }
        }
    }
    Ok(out)
}

/// Get the rendered width (pixels) of a scale-scaled QR.
pub fn render_dimensions(text: &str, scale: usize) -> Result<(usize, usize), CFError> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| {
        CFError::new(
            "QR error",
            format!("Cannot generate QR: {e}"),
            "Input may be too long.",
        )
    })?;
    let w = code.width() * scale;
    Ok((w, w))
}

/// Minimal PNG encoder for a grayscale (8-bit) image. Produces a valid
/// 8-bit grayscale PNG with zlib-compressed scanlines. Avoids the `image`
/// crate entirely (the tree already carries two conflicting image versions).
fn encode_png_gray(pixels: &[u8], width: usize, height: usize) -> Result<Vec<u8>, CFError> {
    if pixels.len() != width * height {
        return Err(CFError::new(
            "QR error",
            "Pixel buffer size does not match dimensions.",
            "Internal error.",
        ));
    }
    // Signature
    let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    // IHDR
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(0); // color type: grayscale
    ihdr.push(0); // compression
    ihdr.push(0); // filter
    ihdr.push(0); // interlace
    push_chunk(&mut png, b"IHDR", &ihdr);

    // IDAT: each scanline prefixed with filter byte 0.
    let mut raw = Vec::with_capacity(height * (1 + width));
    for y in 0..height {
        raw.push(0);
        raw.extend_from_slice(&pixels[y * width..(y + 1) * width]);
    }
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&raw)
        .map_err(|e| CFError::new("QR error", format!("zlib: {e}"), "Internal error."))?;
    let idat = enc
        .finish()
        .map_err(|e| CFError::new("QR error", format!("zlib: {e}"), "Internal error."))?;
    push_chunk(&mut png, b"IDAT", &idat);

    // IEND
    push_chunk(&mut png, b"IEND", &[]);
    Ok(png)
}

fn push_chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    png.extend_from_slice(&(data.len() as u32).to_be_bytes());
    png.extend_from_slice(kind);
    png.extend_from_slice(data);
    let mut crc = Crc32::new();
    crc.update(kind);
    crc.update(data);
    png.extend_from_slice(&crc.finish().to_be_bytes());
}

/// Render a QR code to a grayscale PNG with a quiet zone (border).
/// Returns (png_bytes, side_length_in_pixels).
pub fn render_png(
    text: &str,
    scale: usize,
    quiet_modules: usize,
) -> Result<(Vec<u8>, usize), CFError> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| {
        CFError::new(
            "QR error",
            format!("Cannot generate QR: {e}"),
            "Input may be too long.",
        )
    })?;
    let m = code.width();
    let side = (m + 2 * quiet_modules) * scale;
    let mut img = vec![255u8; side * side];
    for y in 0..m {
        for x in 0..m {
            if code[(x, y)] == qrcode::Color::Dark {
                let px0 = (y + quiet_modules) * scale;
                let py0 = (x + quiet_modules) * scale;
                for dy in 0..scale {
                    for dx in 0..scale {
                        img[(px0 + dy) * side + (py0 + dx)] = 0;
                    }
                }
            }
        }
    }
    let png = encode_png_gray(&img, side, side)?;
    Ok((png, side))
}

/// 32-bit CRC (IEEE) for PNG chunk validation.
struct Crc32 {
    table: [u32; 256],
    crc: u32,
}

impl Crc32 {
    fn new() -> Self {
        let mut table = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB88320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            table[i as usize] = c;
        }
        Self {
            table,
            crc: 0xFFFF_FFFF,
        }
    }
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            let idx = ((self.crc ^ b as u32) & 0xFF) as usize;
            self.crc = self.table[idx] ^ (self.crc >> 8);
        }
    }
    fn finish(&self) -> u32 {
        self.crc ^ 0xFFFF_FFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_square_image() {
        let bytes = render_matrix("vless://test@1.2.3.4:443", 4).unwrap();
        let dim = render_dimensions("vless://test@1.2.3.4:443", 4).unwrap();
        assert_eq!(dim.0, dim.1);
        assert_eq!(bytes.len(), dim.0 * dim.1);
    }

    #[test]
    fn scannable_fixture() {
        let text = "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls#x";
        let dim = render_dimensions(text, 2).unwrap();
        assert!(dim.0 > 0);
    }

    #[test]
    fn png_has_signature_and_dimensions() {
        let (png, side) = render_png("vless://test@1.2.3.4:443", 4, 4).unwrap();
        assert_eq!(&png[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        assert!(side > 0);
        // IHDR width/height (bytes 16..24) should equal `side` in BE.
        let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
        let h = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
        assert_eq!(w as usize, side);
        assert_eq!(h as usize, side);
    }

    #[test]
    fn png_contains_idat_chunk() {
        let (png, _) = render_png("vless://test@1.2.3.4:443", 4, 4).unwrap();
        let s = String::from_utf8_lossy(&png);
        assert!(s.contains("IDAT"));
        assert!(s.contains("IEND"));
    }
}
