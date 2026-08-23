#[repr(C)]
pub struct HeaderData {
    pub header: [u32; 2],
}

#[repr(C)]
pub struct MapData {
    pub data: [u32; 3],
}

#[repr(C)]
pub struct PointerData {
    pub data: [u32; 2],
}

#[repr(C)]
pub struct ReceiveListData {
    pub data: [u32; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Result {
    Success = 0,
    Failure = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TruncatedHeader { actual: usize },
    TruncatedMessage { required: usize, actual: usize },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader { actual } => {
                write!(f, "HIPC header requires 8 bytes, received {actual}")
            }
            Self::TruncatedMessage { required, actual } => write!(
                f,
                "HIPC message requires at least {required} bytes, received {actual}",
            ),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub tag: u16,
    pub pointer_count: u8,
    pub send_count: u8,
    pub receive_count: u8,
    pub exchange_count: u8,
    pub raw_word_count: u16,
    pub receive_static_mode: u8,
    pub receive_list_offset: u16,
    pub has_special_header: bool,
}

impl Header {
    pub const SIZE: usize = 8;

    pub fn parse(data: &[u8]) -> core::result::Result<Self, ParseError> {
        if data.len() < Self::SIZE {
            return Err(ParseError::TruncatedHeader { actual: data.len() });
        }

        let hdr0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let hdr1 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Ok(Self {
            tag: (hdr0 & 0xffff) as u16,
            pointer_count: ((hdr0 >> 16) & 0xf) as u8,
            send_count: ((hdr0 >> 20) & 0xf) as u8,
            receive_count: ((hdr0 >> 24) & 0xf) as u8,
            exchange_count: ((hdr0 >> 28) & 0xf) as u8,
            raw_word_count: (hdr1 & 0x3ff) as u16,
            receive_static_mode: ((hdr1 >> 10) & 0xf) as u8,
            receive_list_offset: ((hdr1 >> 20) & 0x7ff) as u16,
            has_special_header: (hdr1 >> 31) != 0,
        })
    }

    /// Returns the explicit receive-static descriptor count. Mode 2 is the
    /// protocol's automatic mode, whose capacity is supplied out of band.
    pub fn receive_static_count(&self) -> Option<u8> {
        match self.receive_static_mode {
            2 => None,
            mode if mode > 2 => Some(mode - 2),
            _ => Some(0),
        }
    }

    /// Validates the minimum byte length implied by every in-message field.
    /// Automatic receive-static capacity remains an out-of-band receiver input.
    pub fn parse_message(data: &[u8]) -> core::result::Result<Self, ParseError> {
        let header = Self::parse(data)?;
        let mut required = Self::SIZE;

        if header.has_special_header {
            required += 4;
            if data.len() < required {
                return Err(ParseError::TruncatedMessage {
                    required,
                    actual: data.len(),
                });
            }

            let special = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            if special & 1 != 0 {
                required += 8;
            }
            required += usize::from(((special >> 1) & 0xf) as u8) * 4;
            required += usize::from(((special >> 5) & 0xf) as u8) * 4;
        }

        required += usize::from(header.pointer_count) * 8;
        required += usize::from(header.send_count) * 12;
        required += usize::from(header.receive_count) * 12;
        required += usize::from(header.exchange_count) * 12;
        required += usize::from(header.raw_word_count) * 4;
        required += usize::from(header.receive_static_count().unwrap_or(0)) * 8;

        if data.len() < required {
            return Err(ParseError::TruncatedMessage {
                required,
                actual: data.len(),
            });
        }

        Ok(header)
    }
}

pub fn invoke_method<F>(data: &[u8], f: F) -> Result
where
    F: Fn() -> Result,
{
    if Header::parse_message(data).is_err() {
        return Result::Failure;
    }

    f()
}

#[cfg(test)]
mod tests {
    use super::{Header, ParseError, Result, invoke_method};
    use std::cell::Cell;

    fn header_bytes(hdr0: u32, hdr1: u32) -> [u8; Header::SIZE] {
        let mut bytes = [0; Header::SIZE];
        bytes[..4].copy_from_slice(&hdr0.to_le_bytes());
        bytes[4..].copy_from_slice(&hdr1.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_header_fields_as_little_endian() {
        let hdr0 = 0xdcba_4321;
        let hdr1 = 0x8000_0000 | (0x2aa << 20) | (0xb << 10) | 0x155;
        let header = Header::parse(&header_bytes(hdr0, hdr1)).unwrap();

        assert_eq!(header.tag, 0x4321);
        assert_eq!(header.pointer_count, 0xa);
        assert_eq!(header.send_count, 0xb);
        assert_eq!(header.receive_count, 0xc);
        assert_eq!(header.exchange_count, 0xd);
        assert_eq!(header.raw_word_count, 0x155);
        assert_eq!(header.receive_static_mode, 0xb);
        assert_eq!(header.receive_static_count(), Some(9));
        assert_eq!(header.receive_list_offset, 0x2aa);
        assert!(header.has_special_header);
    }

    #[test]
    fn accepts_unaligned_input_without_raw_pointer_reads() {
        let header = header_bytes(0x1234, 0);
        let mut storage = [0xff; Header::SIZE + 1];
        storage[1..].copy_from_slice(&header);

        assert_eq!(Header::parse(&storage[1..]).unwrap().tag, 0x1234);
    }

    #[test]
    fn rejects_every_truncated_header_without_calling_method() {
        let data = header_bytes(0, 0);

        for len in 0..Header::SIZE {
            let called = Cell::new(false);
            let result = invoke_method(&data[..len], || {
                called.set(true);
                Result::Success
            });

            assert_eq!(result, Result::Failure);
            assert!(!called.get());
            assert_eq!(
                Header::parse(&data[..len]),
                Err(ParseError::TruncatedHeader { actual: len })
            );
        }
    }

    #[test]
    fn invokes_method_for_a_complete_header() {
        let called = Cell::new(false);
        let result = invoke_method(&header_bytes(0, 0), || {
            called.set(true);
            Result::Success
        });

        assert_eq!(result, Result::Success);
        assert!(called.get());
    }

    #[test]
    fn uses_the_canonical_receive_list_offset_layout() {
        assert_eq!(
            Header::parse(&header_bytes(0, 0x0010_0000))
                .unwrap()
                .receive_list_offset,
            1
        );
        assert_eq!(
            Header::parse(&header_bytes(0, 0x4000_0000))
                .unwrap()
                .receive_list_offset,
            0x400
        );
        assert_eq!(
            Header::parse(&header_bytes(0, 3 << 10))
                .unwrap()
                .receive_static_count(),
            Some(1)
        );
    }

    #[test]
    fn rejects_truncated_variable_length_content_before_dispatch() {
        let cases = [
            header_bytes(0, 0x8000_0000),
            header_bytes(1 << 16, 0),
            header_bytes(1 << 20, 0),
            header_bytes(0, 1),
            header_bytes(0, 3 << 10),
        ];

        for data in cases {
            let called = Cell::new(false);
            assert_eq!(
                invoke_method(&data, || {
                    called.set(true);
                    Result::Success
                }),
                Result::Failure
            );
            assert!(!called.get());
            assert!(matches!(
                Header::parse_message(&data),
                Err(ParseError::TruncatedMessage { .. })
            ));
        }
    }

    #[test]
    fn accepts_complete_special_header_and_descriptor_content() {
        let hdr0 = (1 << 16) | (1 << 20);
        let hdr1 = 0x8000_0000 | 1;
        let mut message = header_bytes(hdr0, hdr1).to_vec();
        message.extend_from_slice(&(1_u32 | (1 << 1) | (1 << 5)).to_le_bytes());
        message.resize(8 + 4 + 8 + 4 + 4 + 8 + 12 + 4, 0);

        assert!(Header::parse_message(&message).is_ok());
    }
}
