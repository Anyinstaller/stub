use anyhow::{bail, Context, Result};
use toml::Value;

pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Frame {
    pub message_type: String,
    pub body: Vec<u8>,
}

pub fn decode_length(header: [u8; 4]) -> Result<usize> {
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_SIZE {
        bail!("invalid frame length: {length}");
    }
    Ok(length)
}

pub fn encode_frame(body: &[u8]) -> Result<Vec<u8>> {
    if body.is_empty() || body.len() > MAX_FRAME_SIZE {
        bail!("invalid frame body length: {}", body.len());
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

pub fn parse_message(body: &[u8]) -> Result<Frame> {
    if body.is_empty() {
        bail!("frame body is empty");
    }
    if body.len() > MAX_FRAME_SIZE {
        bail!("frame body is too large");
    }
    if body.starts_with(&[0xEF, 0xBB, 0xBF]) {
        bail!("frame body must not start with a BOM");
    }
    let text = std::str::from_utf8(body).context("frame body is not valid UTF-8")?;
    let value: Value = toml::from_str(text).context("frame body is not valid TOML")?;
    let table = value
        .as_table()
        .context("frame TOML root must be a table")?;
    let message_type = table
        .get("type")
        .and_then(Value::as_str)
        .context("frame is missing a string 'type' field")?
        .to_owned();
    if message_type.is_empty() {
        bail!("frame 'type' must not be empty");
    }
    Ok(Frame {
        message_type,
        body: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_roundtrip() {
        let body = b"type = \"startInstall\"";
        let encoded = encode_frame(body).unwrap();
        let length = decode_length(encoded[0..4].try_into().unwrap()).unwrap();
        assert_eq!(length, body.len());
        assert_eq!(&encoded[4..], body);
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(decode_length([0, 0, 0, 0]).is_err());
        assert!(decode_length([0, 0, 0x20, 0]).is_err());
        assert!(decode_length([0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn parses_messages() {
        let frame = parse_message(b"type = \"readyToExit\"").unwrap();
        assert_eq!(frame.message_type, "readyToExit");
        assert!(parse_message(b"value = 1").is_err());
        assert!(parse_message(b"type = 1").is_err());
        assert!(parse_message(b"not toml").is_err());
        assert!(parse_message(b"").is_err());
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert!(parse_message(&[0xff, 0xfe]).is_err());
    }
}
