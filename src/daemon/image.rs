//! DIB ↔ PNG conversion + thumbnail resize + BMP-file wrap.
//!
//! Pure data transformations — no I/O, no Win32 calls, no clipboard
//! interaction. Capture (`src/daemon/capture.rs`) feeds raw CF_DIB bytes
//! through here to derive the canonical content hash, the in-DB thumbnail,
//! and a full-resolution PNG. Promote (`src/daemon/clipboard.rs::set_image`)
//! uses [`dib_to_bmp_file`] to wrap the round-trip CF_DIB into the
//! BMP-file format that `clipboard_win::raw::set_bitmap` requires for
//! reconstructing CF_BITMAP.
//!
//! Scope: BI_RGB at 24 or 32 bits per pixel. That's what Win+PrtScn produces
//! on modern Windows. Other formats (paletted, BI_BITFIELDS, BI_RLE) round-trip
//! via the canonical CF_DIB bytes we store verbatim, but generate no thumbnail.

use anyhow::{anyhow, Result};
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::{ExtendedColorType, ImageEncoder, RgbaImage};

/// Largest CF_DIB we'll accept on capture. ~64 MiB covers any realistic 4K
/// or 8K screenshot (3840×2160×4 = 32 MiB; 7680×4320×4 = 132 MiB exceeds).
/// 8K is genuinely uncommon and the cap keeps a single rogue clipboard write
/// from blowing up the encrypt + insert path.
pub const IMAGE_DIB_CAP_BYTES: usize = 64 * 1024 * 1024;

/// Thumbnail bounding box for the picker row. Picker renders at 64×64
/// logical px; 256 max gives 4× headroom for HiDPI displays.
pub const THUMB_MAX_DIM: u32 = 256;

/// Sizes of fixed-layout DIB headers. Read directly off `BITMAPINFOHEADER` /
/// `BITMAPFILEHEADER` per Win32 docs.
const BITMAPFILEHEADER_LEN: usize = 14;
const BITMAPINFOHEADER_LEN: usize = 40;
const BI_RGB: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageMeta {
    pub width: u32,
    pub height: u32,
    pub bpp: u16,
}

/// Parse just enough of a CF_DIB byte slice to extract pixel dimensions
/// and bits-per-pixel. Returns `None` for malformed slices or unsupported
/// formats (non-BI_RGB, weird bpp). The caller still stores the verbatim
/// bytes — this is only for the preview string and the thumbnail decoder.
pub fn parse_dib_meta(dib: &[u8]) -> Option<ImageMeta> {
    if dib.len() < BITMAPINFOHEADER_LEN {
        return None;
    }
    let bi_size = u32::from_le_bytes(dib[0..4].try_into().ok()?);
    // BITMAPV4HEADER is 108 bytes, V5 is 124. Anything ≥ 40 starts with the
    // same fields, so we can read width/height/bpp regardless of which
    // header version we got handed.
    if (bi_size as usize) < BITMAPINFOHEADER_LEN {
        return None;
    }
    let width = i32::from_le_bytes(dib[4..8].try_into().ok()?);
    let height = i32::from_le_bytes(dib[8..12].try_into().ok()?);
    let bpp = u16::from_le_bytes(dib[14..16].try_into().ok()?);
    let compression = u32::from_le_bytes(dib[16..20].try_into().ok()?);

    if width <= 0 || height == 0 {
        return None;
    }
    // BI_BITFIELDS (3) is technically still RGB but with explicit color
    // masks — handling it correctly requires reading the masks and remapping
    // channels. Defer until a user reports needing it; for now the canonical
    // CF_DIB bytes round-trip via promote regardless.
    if compression != BI_RGB {
        return None;
    }
    if !matches!(bpp, 24 | 32) {
        return None;
    }
    Some(ImageMeta {
        width: width as u32,
        height: height.unsigned_abs(),
        bpp,
    })
}

/// Decode a CF_DIB bytestring into an RGBA image. Handles BI_RGB at 24 or
/// 32 bits per pixel, top-down (negative biHeight) and bottom-up (positive)
/// layouts. DIB pixel rows are padded to 4-byte stride; we honor that.
pub fn dib_to_rgba(dib: &[u8]) -> Option<RgbaImage> {
    let meta = parse_dib_meta(dib)?;
    let bi_size = u32::from_le_bytes(dib[0..4].try_into().ok()?) as usize;
    let height_signed = i32::from_le_bytes(dib[8..12].try_into().ok()?);
    let top_down = height_signed < 0;
    let bytes_per_pixel = (meta.bpp / 8) as usize;
    let stride = (meta.width as usize * bytes_per_pixel).div_ceil(4) * 4;
    let pixel_offset = bi_size; // BI_RGB has no color masks; no palette at 24/32 bpp.
    let needed = pixel_offset + stride * meta.height as usize;
    if dib.len() < needed {
        return None;
    }

    let mut out = RgbaImage::new(meta.width, meta.height);
    for row in 0..meta.height {
        // Bottom-up: row 0 is the last row of the source.
        let src_row = if top_down {
            row as usize
        } else {
            (meta.height - 1 - row) as usize
        };
        let src_start = pixel_offset + src_row * stride;
        for col in 0..meta.width as usize {
            let off = src_start + col * bytes_per_pixel;
            // DIB byte order is BGR(A) in memory.
            let b = dib[off];
            let g = dib[off + 1];
            let r = dib[off + 2];
            let a = if bytes_per_pixel == 4 {
                // Win+PrtScn writes the alpha byte as 0 ("undefined"). Treat
                // 0 as opaque so the picker renders the screenshot correctly
                // instead of a transparent void; opt back into real alpha if
                // any non-zero value shows up in the buffer.
                let raw = dib[off + 3];
                if raw == 0 {
                    255
                } else {
                    raw
                }
            } else {
                255
            };
            out.put_pixel(col as u32, row, image::Rgba([r, g, b, a]));
        }
    }
    Some(out)
}

/// PNG-encode an RGBA image. Uses `CompressionType::Fast` + the default
/// adaptive filter to keep capture-thread latency low (~50–100ms for 4K).
pub fn rgba_to_png(img: &RgbaImage) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(img.as_raw().len() / 8);
    let encoder =
        PngEncoder::new_with_quality(&mut buf, CompressionType::Fast, FilterType::Adaptive);
    encoder
        .write_image(
            img.as_raw(),
            img.width(),
            img.height(),
            ExtendedColorType::Rgba8,
        )
        .map_err(|e| anyhow!("PNG encode: {e}"))?;
    Ok(buf)
}

/// Downscale `img` to fit within `max_dim x max_dim`, preserving aspect
/// ratio. Returns the input as-is if both dimensions are already within
/// bounds — no point round-tripping pixels for already-tiny images.
pub fn thumbnail(img: &RgbaImage, max_dim: u32) -> RgbaImage {
    let (w, h) = (img.width(), img.height());
    if w <= max_dim && h <= max_dim {
        return img.clone();
    }
    // Compute scaled dimensions in u32 with one f32 division — image's
    // resize_exact takes target dims directly.
    let scale = (max_dim as f32 / w as f32).min(max_dim as f32 / h as f32);
    let new_w = (w as f32 * scale).round().max(1.0) as u32;
    let new_h = (h as f32 * scale).round().max(1.0) as u32;
    image::imageops::resize(img, new_w, new_h, image::imageops::FilterType::Triangle)
}

/// Wrap raw CF_DIB bytes into BMP-file format (prepend a 14-byte
/// `BITMAPFILEHEADER`). `clipboard_win::raw::set_bitmap` requires this
/// shape — it parses both headers, then calls `CreateDIBitmap` to
/// reconstruct CF_BITMAP for legacy GDI receivers. Returns `None` if the
/// DIB is too short to even hold its own info header.
pub fn dib_to_bmp_file(dib: &[u8]) -> Option<Vec<u8>> {
    if dib.len() < BITMAPINFOHEADER_LEN {
        return None;
    }
    let bi_size = u32::from_le_bytes(dib[0..4].try_into().ok()?) as usize;
    if dib.len() < bi_size {
        return None;
    }
    // Pixel offset must skip the info header AND any color masks (12 bytes
    // for BI_BITFIELDS at 16/32-bit) AND any palette (RGBQUAD per entry).
    // For 24/32-bit BI_RGB the offset is just info-header-size; for paletted
    // formats we add palette bytes.
    let bpp = u16::from_le_bytes(dib[14..16].try_into().ok()?);
    let compression = u32::from_le_bytes(dib[16..20].try_into().ok()?);
    let bi_clr_used = u32::from_le_bytes(dib[32..36].try_into().ok()?);

    let palette_entries = match (bpp, bi_clr_used) {
        (1 | 4 | 8, 0) => 1u32 << bpp,
        (1 | 4 | 8, n) => n,
        _ => 0,
    };
    let palette_bytes = palette_entries as usize * 4;
    let mask_bytes = if compression == 3 { 12 } else { 0 };
    let pixel_offset = BITMAPFILEHEADER_LEN + bi_size + mask_bytes + palette_bytes;
    let total = BITMAPFILEHEADER_LEN + dib.len();

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&0x4D42u16.to_le_bytes()); // "BM"
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved1
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    out.extend_from_slice(&(pixel_offset as u32).to_le_bytes());
    out.extend_from_slice(dib);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal BITMAPINFOHEADER + pixel data DIB for tests. `top_down`
    /// = true emits a negative biHeight. Pixel layout: BGR(A) per Win32.
    fn synth_dib(width: u32, height: u32, bpp: u16, top_down: bool, pixels: &[u8]) -> Vec<u8> {
        let mut dib = Vec::new();
        // BITMAPINFOHEADER (40 bytes)
        dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
        dib.extend_from_slice(&(width as i32).to_le_bytes()); // biWidth
        let h = if top_down {
            -(height as i32)
        } else {
            height as i32
        };
        dib.extend_from_slice(&h.to_le_bytes()); // biHeight
        dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
        dib.extend_from_slice(&bpp.to_le_bytes()); // biBitCount
        dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression = BI_RGB
        dib.extend_from_slice(&0u32.to_le_bytes()); // biSizeImage
        dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
        dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant
        dib.extend_from_slice(pixels);
        dib
    }

    #[test]
    fn parse_dib_meta_24bit() {
        // 2x2 24-bit BI_RGB: stride = ceil(2*3/4)*4 = 8, total = 16 bytes.
        let pixels = vec![0u8; 16];
        let dib = synth_dib(2, 2, 24, false, &pixels);
        let m = parse_dib_meta(&dib).expect("should parse");
        assert_eq!(m.width, 2);
        assert_eq!(m.height, 2);
        assert_eq!(m.bpp, 24);
    }

    #[test]
    fn parse_dib_meta_32bit_top_down() {
        // 4x3 32-bit, top-down. Stride = 16, total = 48.
        let pixels = vec![0u8; 48];
        let dib = synth_dib(4, 3, 32, true, &pixels);
        let m = parse_dib_meta(&dib).expect("should parse");
        assert_eq!(m.width, 4);
        assert_eq!(m.height, 3);
        assert_eq!(m.bpp, 32);
    }

    #[test]
    fn parse_dib_meta_rejects_unsupported() {
        // 8-bit paletted — out of scope.
        let dib = synth_dib(2, 2, 8, false, &[0u8; 16]);
        assert!(parse_dib_meta(&dib).is_none());
        // Truncated header.
        assert!(parse_dib_meta(&[0u8; 10]).is_none());
    }

    #[test]
    fn dib_to_rgba_round_trip_2x2_bottom_up() {
        // 2x2 32-bit BGRA. Stride = 8, total 16 bytes.
        // Visual layout (top → bottom in destination):
        //   row 0: red,   green
        //   row 1: blue,  white
        // In bottom-up DIB memory, row 0 of the buffer = bottom row of image.
        let pixels = vec![
            // bottom row in memory = top of source's row 1 (blue, white)
            0xFF, 0x00, 0x00, 0x00, // BGRA: blue
            0xFF, 0xFF, 0xFF, 0x00, // BGRA: white
            // top row in memory = source's row 0 (red, green)
            0x00, 0x00, 0xFF, 0x00, // BGRA: red
            0x00, 0xFF, 0x00, 0x00, // BGRA: green
        ];
        let dib = synth_dib(2, 2, 32, false, &pixels);
        let rgba = dib_to_rgba(&dib).expect("decode");
        assert_eq!(rgba.dimensions(), (2, 2));
        // Row 0 should be red, green (bottom-up flip applied).
        assert_eq!(rgba.get_pixel(0, 0).0, [255, 0, 0, 255]);
        assert_eq!(rgba.get_pixel(1, 0).0, [0, 255, 0, 255]);
        // Row 1 should be blue, white.
        assert_eq!(rgba.get_pixel(0, 1).0, [0, 0, 255, 255]);
        assert_eq!(rgba.get_pixel(1, 1).0, [255, 255, 255, 255]);
    }

    #[test]
    fn dib_to_rgba_top_down_matches_bottom_up_visually() {
        // Same pixel data viewed top-down should produce mirrored output.
        let pixels = vec![
            0x00, 0x00, 0xFF, 0x00, // red
            0x00, 0xFF, 0x00, 0x00, // green
            0xFF, 0x00, 0x00, 0x00, // blue
            0xFF, 0xFF, 0xFF, 0x00, // white
        ];
        let dib_td = synth_dib(2, 2, 32, true, &pixels);
        let rgba = dib_to_rgba(&dib_td).expect("decode");
        // Top-down: source row 0 = red, green; source row 1 = blue, white.
        assert_eq!(rgba.get_pixel(0, 0).0, [255, 0, 0, 255]);
        assert_eq!(rgba.get_pixel(1, 0).0, [0, 255, 0, 255]);
        assert_eq!(rgba.get_pixel(0, 1).0, [0, 0, 255, 255]);
        assert_eq!(rgba.get_pixel(1, 1).0, [255, 255, 255, 255]);
    }

    #[test]
    fn thumbnail_no_scale_when_within_bounds() {
        let img = RgbaImage::new(100, 50);
        let t = thumbnail(&img, 256);
        assert_eq!(t.dimensions(), (100, 50));
    }

    #[test]
    fn thumbnail_preserves_aspect_ratio_landscape() {
        let img = RgbaImage::new(1000, 500);
        let t = thumbnail(&img, 256);
        // Expected: 256 wide, 128 tall.
        assert_eq!(t.dimensions(), (256, 128));
    }

    #[test]
    fn thumbnail_preserves_aspect_ratio_portrait() {
        let img = RgbaImage::new(500, 1000);
        let t = thumbnail(&img, 256);
        // Expected: 128 wide, 256 tall.
        assert_eq!(t.dimensions(), (128, 256));
    }

    #[test]
    fn dib_to_bmp_file_offset_correct_for_24bit() {
        // 2x2 24-bit, no palette, no masks. bfOffBits should be 14 + 40 = 54.
        let pixels = vec![0u8; 16];
        let dib = synth_dib(2, 2, 24, false, &pixels);
        let bmp = dib_to_bmp_file(&dib).expect("wrap");
        assert_eq!(&bmp[0..2], b"BM");
        let total = u32::from_le_bytes(bmp[2..6].try_into().unwrap());
        assert_eq!(total as usize, bmp.len());
        let off = u32::from_le_bytes(bmp[10..14].try_into().unwrap());
        assert_eq!(off, 14 + 40);
    }

    #[test]
    fn dib_to_bmp_file_rejects_truncated() {
        assert!(dib_to_bmp_file(&[0u8; 10]).is_none());
    }

    #[test]
    fn rgba_to_png_round_trip() {
        let mut img = RgbaImage::new(4, 4);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgba([x as u8 * 60, y as u8 * 60, 0, 255]);
        }
        let png = rgba_to_png(&img).expect("encode");
        // Decode back via image::load_from_memory and assert pixel equality.
        let decoded = image::load_from_memory(&png).expect("decode").to_rgba8();
        assert_eq!(decoded.dimensions(), img.dimensions());
        for (a, b) in img.pixels().zip(decoded.pixels()) {
            assert_eq!(a.0, b.0);
        }
    }
}
