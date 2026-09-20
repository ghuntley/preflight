//! Typed subprocess protocol shared by the isolated Rust worker and proxy.
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Segment {
    pub text: String,
    pub page: Option<usize>,
    pub bounds: Option<[u32; 4]>,
}
#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub complete: bool,
    pub segments: Vec<Segment>,
    #[serde(default)]
    pub pages: Vec<String>,
    #[serde(default)]
    pub pdf: bool,
}

/// @cc [owner:ghuntley,label:security] scaled-bounds-cover
/// Mapping a valid box from a reduced image to the original MUST round its lower
/// bounds down and upper bounds up so reconstruction never loses edge pixels.
pub fn scale_bounds(bounds: [u32; 4], source: [u32; 2], target: [u32; 2]) -> [u32; 4] {
    assert!(source[0] > 0 && source[1] > 0);
    [
        (u64::from(bounds[0]) * u64::from(target[0]) / u64::from(source[0])) as u32,
        (u64::from(bounds[1]) * u64::from(target[1]) / u64::from(source[1])) as u32,
        (u64::from(bounds[2]) * u64::from(target[0])).div_ceil(u64::from(source[0])) as u32,
        (u64::from(bounds[3]) * u64::from(target[1])).div_ceil(u64::from(source[1])) as u32,
    ]
}

/// @cc [owner:ghuntley,label:security] rotation-source-map
/// OCR boxes from quarter-turn rotated views MUST be mapped back to original
/// pixel coordinates before any redaction is applied.
pub fn unrotate_bounds(
    [x1, y1, x2, y2]: [u32; 4],
    [width, height]: [u32; 2],
    rotation: u8,
) -> [u32; 4] {
    match rotation % 4 {
        0 => [x1, y1, x2, y2],
        1 => [y1, height.saturating_sub(x2), y2, height.saturating_sub(x1)],
        2 => [
            width.saturating_sub(x2),
            height.saturating_sub(y2),
            width.saturating_sub(x1),
            height.saturating_sub(y1),
        ],
        _ => [width.saturating_sub(y2), x1, width.saturating_sub(y1), x2],
    }
}
