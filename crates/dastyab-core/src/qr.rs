//! QR matrix rendering for share links (uses the `qrcode` crate).

use crate::error::CFError;

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
}
