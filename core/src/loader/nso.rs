use crate::memory::{AddressSpace, MemoryError, Permissions};
use lz4_flex::block;
use sha2::{Digest, Sha256};

pub const NSO_HEADER_SIZE: usize = 0x100;
pub const MAX_SECTION_SIZE: u32 = 512 * 1024 * 1024;
pub const MAX_IMAGE_SIZE: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Text,
    ReadOnly,
    Data,
}

impl SectionKind {
    fn index(self) -> usize {
        match self {
            Self::Text => 0,
            Self::ReadOnly => 1,
            Self::Data => 2,
        }
    }

    fn permissions(self) -> Permissions {
        match self {
            Self::Text => Permissions::READ | Permissions::EXECUTE,
            Self::ReadOnly => Permissions::READ,
            Self::Data => Permissions::READ | Permissions::WRITE,
        }
    }
}

impl std::fmt::Display for SectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => f.write_str("text"),
            Self::ReadOnly => f.write_str("rodata"),
            Self::Data => f.write_str("data"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsoSegment {
    pub kind: SectionKind,
    pub memory_offset: u32,
    pub alignment_or_bss_size: u32,
    pub compressed: bool,
    pub hashed: bool,
    pub data: Vec<u8>,
}

impl NsoSegment {
    pub fn bss_size(&self) -> u32 {
        if self.kind == SectionKind::Data {
            self.alignment_or_bss_size
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsoImage {
    pub version: u32,
    pub flags: u32,
    pub build_id: [u8; 0x20],
    pub segments: [NsoSegment; 3],
}

#[derive(Debug, Clone, Copy)]
struct SegmentLayout {
    kind: SectionKind,
    start: usize,
    end: usize,
    memory_offset: u32,
    decompressed_size: u32,
    alignment_or_bss_size: u32,
    compressed: bool,
    hashed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsoError {
    TruncatedHeader {
        actual: usize,
    },
    InvalidMagic([u8; 4]),
    SectionTooLarge {
        kind: SectionKind,
        size: u64,
    },
    ImageTooLarge {
        size: u64,
    },
    RangeOverflow {
        kind: SectionKind,
    },
    SectionOutOfBounds {
        kind: SectionKind,
    },
    FileSectionOverlap {
        first: SectionKind,
        second: SectionKind,
    },
    MemorySectionOverlap {
        first: SectionKind,
        second: SectionKind,
    },
    DecompressionFailed {
        kind: SectionKind,
    },
    HashMismatch {
        kind: SectionKind,
    },
    Memory(MemoryError),
}

impl std::fmt::Display for NsoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader { actual } => {
                write!(
                    f,
                    "NSO header requires {NSO_HEADER_SIZE} bytes, received {actual}"
                )
            }
            Self::InvalidMagic(magic) => write!(f, "invalid NSO magic {magic:02x?}"),
            Self::SectionTooLarge { kind, size } => {
                write!(f, "{kind} section is too large: {size:#x}")
            }
            Self::ImageTooLarge { size } => {
                write!(f, "NSO image is too large: {size:#x}")
            }
            Self::RangeOverflow { kind } => write!(f, "{kind} section range overflowed"),
            Self::SectionOutOfBounds { kind } => write!(f, "{kind} section is outside the file"),
            Self::FileSectionOverlap { first, second } => {
                write!(f, "{first} and {second} file ranges overlap")
            }
            Self::MemorySectionOverlap { first, second } => {
                write!(f, "{first} and {second} memory ranges overlap")
            }
            Self::DecompressionFailed { kind } => {
                write!(f, "failed to decompress {kind} section")
            }
            Self::HashMismatch { kind } => write!(f, "{kind} section hash does not match"),
            Self::Memory(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for NsoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            _ => None,
        }
    }
}

impl From<MemoryError> for NsoError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

impl NsoImage {
    pub fn parse(file: &[u8]) -> Result<Self, NsoError> {
        Self::parse_with_limits(file, MAX_SECTION_SIZE, MAX_IMAGE_SIZE)
    }

    pub fn parse_with_max_section_size(
        file: &[u8],
        max_section_size: u32,
    ) -> Result<Self, NsoError> {
        Self::parse_with_limits(file, max_section_size, u64::from(max_section_size) * 3)
    }

    pub fn parse_with_limits(
        file: &[u8],
        max_section_size: u32,
        max_image_size: u64,
    ) -> Result<Self, NsoError> {
        if file.len() < NSO_HEADER_SIZE {
            return Err(NsoError::TruncatedHeader { actual: file.len() });
        }

        let magic = [file[0], file[1], file[2], file[3]];
        if &magic != b"NSO0" {
            return Err(NsoError::InvalidMagic(magic));
        }

        let version = read_u32(file, 0x04);
        let flags = read_u32(file, 0x0c);
        let build_id = file[0x40..0x60]
            .try_into()
            .expect("validated NSO header contains build id");

        let kinds = [SectionKind::Text, SectionKind::ReadOnly, SectionKind::Data];
        let max_section_size_bytes = u64::from(max_section_size);
        let mut layouts = Vec::with_capacity(3);
        let mut file_ranges: Vec<(SectionKind, usize, usize)> = Vec::with_capacity(3);
        let mut memory_ranges: Vec<(SectionKind, u64, u64)> = Vec::with_capacity(3);
        let mut total_memory_size = 0_u64;

        for kind in kinds {
            let index = kind.index();
            let header_offset = 0x10 + index * 0x10;
            let file_offset = read_u32(file, header_offset);
            let memory_offset = read_u32(file, header_offset + 4);
            let decompressed_size = read_u32(file, header_offset + 8);
            let alignment_or_bss_size = read_u32(file, header_offset + 12);
            let compressed_size = read_u32(file, 0x60 + index * 4);
            let compressed = flags & (1 << index) != 0;
            let hashed = flags & (1 << (index + 3)) != 0;

            let bss_size = if kind == SectionKind::Data {
                u64::from(alignment_or_bss_size)
            } else {
                0
            };
            let memory_size = u64::from(decompressed_size)
                .checked_add(bss_size)
                .ok_or(NsoError::RangeOverflow { kind })?;
            if memory_size > max_section_size_bytes
                || u64::from(compressed_size) > max_section_size_bytes
            {
                return Err(NsoError::SectionTooLarge {
                    kind,
                    size: memory_size.max(u64::from(compressed_size)),
                });
            }
            total_memory_size = total_memory_size
                .checked_add(memory_size)
                .ok_or(NsoError::ImageTooLarge { size: u64::MAX })?;
            if total_memory_size > max_image_size {
                return Err(NsoError::ImageTooLarge {
                    size: total_memory_size,
                });
            }

            let stored_size = if compressed {
                compressed_size
            } else {
                decompressed_size
            };
            let start =
                usize::try_from(file_offset).map_err(|_| NsoError::RangeOverflow { kind })?;
            let stored_size =
                usize::try_from(stored_size).map_err(|_| NsoError::RangeOverflow { kind })?;
            let end = start
                .checked_add(stored_size)
                .ok_or(NsoError::RangeOverflow { kind })?;
            if end > file.len() || (stored_size != 0 && start < NSO_HEADER_SIZE) {
                return Err(NsoError::SectionOutOfBounds { kind });
            }

            if stored_size != 0 {
                for (other_kind, other_start, other_end) in &file_ranges {
                    if start < *other_end && *other_start < end {
                        return Err(NsoError::FileSectionOverlap {
                            first: *other_kind,
                            second: kind,
                        });
                    }
                }
                file_ranges.push((kind, start, end));
            }

            let memory_start = u64::from(memory_offset);
            let memory_end = memory_start
                .checked_add(memory_size)
                .ok_or(NsoError::RangeOverflow { kind })?;
            if memory_size != 0 {
                for (other_kind, other_start, other_end) in &memory_ranges {
                    if memory_start < *other_end && *other_start < memory_end {
                        return Err(NsoError::MemorySectionOverlap {
                            first: *other_kind,
                            second: kind,
                        });
                    }
                }
                memory_ranges.push((kind, memory_start, memory_end));
            }
            layouts.push(SegmentLayout {
                kind,
                start,
                end,
                memory_offset,
                decompressed_size,
                alignment_or_bss_size,
                compressed,
                hashed,
            });
        }

        let mut segments = Vec::with_capacity(3);
        for layout in layouts {
            let payload = &file[layout.start..layout.end];
            let data = if layout.compressed {
                block::decompress(payload, layout.decompressed_size as usize)
                    .map_err(|_| NsoError::DecompressionFailed { kind: layout.kind })?
            } else {
                payload.to_vec()
            };

            if data.len() != layout.decompressed_size as usize {
                return Err(NsoError::DecompressionFailed { kind: layout.kind });
            }

            if layout.hashed {
                let index = layout.kind.index();
                let expected = &file[0xa0 + index * 0x20..0xc0 + index * 0x20];
                let actual = Sha256::digest(&data);
                if actual[..] != expected[..] {
                    return Err(NsoError::HashMismatch { kind: layout.kind });
                }
            }

            segments.push(NsoSegment {
                kind: layout.kind,
                memory_offset: layout.memory_offset,
                alignment_or_bss_size: layout.alignment_or_bss_size,
                compressed: layout.compressed,
                hashed: layout.hashed,
                data,
            });
        }
        let segments = segments
            .try_into()
            .expect("the parser always creates exactly three NSO segments");

        Ok(Self {
            version,
            flags,
            build_id,
            segments,
        })
    }

    pub fn map_into(
        &self,
        address_space: &mut AddressSpace,
        image_base: u64,
    ) -> Result<(), NsoError> {
        let mut staged = AddressSpace::new(address_space.page_size())?;
        let page_size = staged.page_size();

        for segment in &self.segments {
            let total_size = u64::try_from(segment.data.len())
                .map_err(|_| NsoError::RangeOverflow { kind: segment.kind })?
                .checked_add(u64::from(segment.bss_size()))
                .ok_or(NsoError::RangeOverflow { kind: segment.kind })?;
            if total_size == 0 {
                continue;
            }
            let map_size = align_up(total_size, page_size)
                .ok_or(NsoError::RangeOverflow { kind: segment.kind })?;
            let address = image_base
                .checked_add(u64::from(segment.memory_offset))
                .ok_or(NsoError::RangeOverflow { kind: segment.kind })?;

            staged.map_zeroed(address, map_size, Permissions::READ | Permissions::WRITE)?;
            if !segment.data.is_empty() {
                staged.write(address, &segment.data)?;
            }
            staged.protect(address, map_size, segment.kind.permissions())?;
        }

        address_space.merge_disjoint(staged)?;
        Ok(())
    }
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|value| value & !(alignment - 1))
}

#[cfg(test)]
mod tests {
    use super::{NSO_HEADER_SIZE, NsoError, NsoImage, SectionKind};
    use crate::memory::{AddressSpace, MemoryError};
    use lz4_flex::block;
    use sha2::{Digest, Sha256};

    fn put_u32(output: &mut [u8], offset: usize, value: u32) {
        output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_nso(compressed_mask: u32) -> Vec<u8> {
        let payloads = [b"text".to_vec(), b"rodt".to_vec(), b"data".to_vec()];
        let memory_offsets = [0, 0x1000, 0x2000];
        let mut header = vec![0; NSO_HEADER_SIZE];
        header[..4].copy_from_slice(b"NSO0");
        put_u32(&mut header, 0x04, 1);
        put_u32(&mut header, 0x0c, compressed_mask | 0x38);
        header[0x40..0x60].fill(0x5a);

        let mut stored_payloads = Vec::new();
        let mut file_offset = NSO_HEADER_SIZE as u32;
        for index in 0..3 {
            let compressed = compressed_mask & (1 << index) != 0;
            let stored = if compressed {
                block::compress(&payloads[index])
            } else {
                payloads[index].clone()
            };
            let segment_offset = 0x10 + index * 0x10;
            put_u32(&mut header, segment_offset, file_offset);
            put_u32(&mut header, segment_offset + 4, memory_offsets[index]);
            put_u32(
                &mut header,
                segment_offset + 8,
                payloads[index].len() as u32,
            );
            put_u32(
                &mut header,
                segment_offset + 12,
                if index == 2 { 8 } else { 1 },
            );
            put_u32(&mut header, 0x60 + index * 4, stored.len() as u32);
            let hash = Sha256::digest(&payloads[index]);
            header[0xa0 + index * 0x20..0xc0 + index * 0x20].copy_from_slice(&hash);
            file_offset += stored.len() as u32;
            stored_payloads.push(stored);
        }

        for payload in stored_payloads {
            header.extend_from_slice(&payload);
        }
        header
    }

    #[test]
    fn parses_hashes_and_decompresses_synthetic_sections() {
        let image = NsoImage::parse(&synthetic_nso(0b101)).unwrap();

        assert_eq!(image.version, 1);
        assert_eq!(image.build_id, [0x5a; 0x20]);
        assert_eq!(image.segments[0].data, b"text");
        assert!(image.segments[0].compressed);
        assert!(!image.segments[1].compressed);
        assert_eq!(image.segments[2].bss_size(), 8);
    }

    #[test]
    fn maps_sections_transactionally_with_expected_permissions() {
        let image = NsoImage::parse(&synthetic_nso(0)).unwrap();
        let mut memory = AddressSpace::new(0x1000).unwrap();
        image.map_into(&mut memory, 0x7100_0000).unwrap();

        assert_eq!(memory.fetch(0x7100_0000, 4).unwrap(), b"text");
        assert_eq!(memory.read(0x7100_1000, 4).unwrap(), b"rodt");
        assert_eq!(memory.read(0x7100_2000, 4).unwrap(), b"data");
        assert_eq!(memory.read(0x7100_2004, 8).unwrap(), &[0; 8]);
        assert!(matches!(
            memory.write(0x7100_0000, &[0]),
            Err(MemoryError::PermissionDenied { .. })
        ));
        memory.write(0x7100_2000, b"D").unwrap();
        assert_eq!(memory.read(0x7100_2000, 1).unwrap(), b"D");
    }

    #[test]
    fn rejects_truncation_hash_mismatch_and_file_overlap() {
        assert!(matches!(
            NsoImage::parse(&[0; 8]),
            Err(NsoError::TruncatedHeader { .. })
        ));

        let mut oversized = synthetic_nso(0);
        put_u32(&mut oversized, 0x18, 2 * 1024 * 1024);
        assert!(matches!(
            NsoImage::parse_with_max_section_size(&oversized, 1024 * 1024),
            Err(NsoError::SectionTooLarge {
                kind: SectionKind::Text,
                ..
            })
        ));

        let mut oversized_data_and_bss = synthetic_nso(0);
        put_u32(&mut oversized_data_and_bss, 0x3c, 8);
        assert!(matches!(
            NsoImage::parse_with_max_section_size(&oversized_data_and_bss, 8),
            Err(NsoError::SectionTooLarge {
                kind: SectionKind::Data,
                size: 12,
            })
        ));

        let mut bad_hash = synthetic_nso(0);
        bad_hash[NSO_HEADER_SIZE] ^= 0xff;
        assert!(matches!(
            NsoImage::parse(&bad_hash),
            Err(NsoError::HashMismatch {
                kind: SectionKind::Text
            })
        ));

        let mut overlap = synthetic_nso(0);
        let text_offset = u32::from_le_bytes(overlap[0x10..0x14].try_into().unwrap());
        put_u32(&mut overlap, 0x20, text_offset);
        assert!(matches!(
            NsoImage::parse(&overlap),
            Err(NsoError::FileSectionOverlap { .. })
        ));
    }

    #[test]
    fn accepts_zero_length_sections_without_false_overlap() {
        let mut image = synthetic_nso(0);
        let text_file_offset = u32::from_le_bytes(image[0x10..0x14].try_into().unwrap());

        put_u32(&mut image, 0x20, text_file_offset + 1);
        put_u32(&mut image, 0x24, 1);
        put_u32(&mut image, 0x28, 0);
        put_u32(&mut image, 0x64, 0);
        image[0xc0..0xe0].copy_from_slice(&Sha256::digest(b""));

        let parsed = NsoImage::parse(&image).unwrap();
        assert!(parsed.segments[1].data.is_empty());
    }

    #[test]
    fn rejects_aggregate_image_size_before_decompression() {
        let mut image = synthetic_nso(0b001);
        image[NSO_HEADER_SIZE] ^= 0xff;

        assert!(matches!(
            NsoImage::parse_with_limits(&image, 64, 19),
            Err(NsoError::ImageTooLarge { size: 20 })
        ));
    }

    #[test]
    fn failed_mapping_leaves_the_address_space_unchanged() {
        let image = NsoImage::parse(&synthetic_nso(0)).unwrap();
        let mut memory = AddressSpace::new(0x1000).unwrap();
        memory
            .map_zeroed(0x7100_1000, 0x1000, crate::memory::Permissions::READ)
            .unwrap();

        assert!(image.map_into(&mut memory, 0x7100_0000).is_err());
        assert_eq!(memory.regions().count(), 1);
        assert!(memory.read(0x7100_0000, 1).is_err());
    }
}
