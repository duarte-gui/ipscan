//! Clipboard copy over OSC52 — works across SSH, with no dependency.
//!
//! The `ESC ] 52 ; c ; <base64> BEL` sequence asks the terminal to put the text
//! on the clipboard. Supported by tmux, kitty, foot, alacritty, wezterm, iTerm2
//! and others. There is no acknowledgement: this is best effort.

use std::io::Write;

pub fn copy(text: &str) {
    let b64 = base64(text.as_bytes());
    // Write straight to the terminal (stdout is still in alternate screen).
    let seq = format!("\x1b]52;c;{}\x07", b64);
    if let Ok(mut out) = std::io::stdout().lock().write_all(seq.as_bytes()).map(|_| std::io::stdout()) {
        let _ = out.flush();
    }
}

/// Standard base64 (RFC 4648), with no external dependency.
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64;
    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"AA:BB:CC:DD:EE:FF"), "QUE6QkI6Q0M6REQ6RUU6RkY=");
    }
}
