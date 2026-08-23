use std::collections::BTreeMap;
use std::ops::{BitOr, BitOrAssign};

pub const DEFAULT_PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions(u8);

impl Permissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

impl BitOr for Permissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Permissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    InvalidPageSize(u64),
    PageSizeMismatch {
        expected: u64,
        actual: u64,
    },
    ZeroSize,
    Unaligned {
        value: u64,
        alignment: u64,
    },
    AddressOverflow,
    RegionTooLarge(u64),
    AllocationFailed(u64),
    Overlap {
        base: u64,
    },
    NotMapped {
        address: u64,
        size: u64,
    },
    PermissionDenied {
        address: u64,
        required: Permissions,
    },
    RegionSizeMismatch {
        base: u64,
        expected: u64,
        actual: u64,
    },
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPageSize(size) => write!(f, "invalid page size {size:#x}"),
            Self::PageSizeMismatch { expected, actual } => write!(
                f,
                "address-space page size {actual:#x} does not match {expected:#x}"
            ),
            Self::ZeroSize => write!(f, "memory region size must be non-zero"),
            Self::Unaligned { value, alignment } => {
                write!(f, "{value:#x} is not aligned to {alignment:#x}")
            }
            Self::AddressOverflow => write!(f, "memory address range overflowed"),
            Self::RegionTooLarge(size) => {
                write!(
                    f,
                    "memory region {size:#x} does not fit the host address space"
                )
            }
            Self::AllocationFailed(size) => {
                write!(f, "failed to allocate memory region of {size:#x} bytes")
            }
            Self::Overlap { base } => write!(f, "memory region overlaps mapping at {base:#x}"),
            Self::NotMapped { address, size } => {
                write!(f, "range {address:#x}..+{size:#x} is not mapped")
            }
            Self::PermissionDenied { address, required } => {
                write!(f, "range at {address:#x} lacks permission {required:?}")
            }
            Self::RegionSizeMismatch {
                base,
                expected,
                actual,
            } => write!(
                f,
                "mapping at {base:#x} has size {actual:#x}, expected {expected:#x}"
            ),
        }
    }
}

impl std::error::Error for MemoryError {}

#[derive(Debug, Clone)]
pub struct Region {
    base: u64,
    size: u64,
    permissions: Permissions,
    data: Vec<u8>,
}

impl Region {
    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn permissions(&self) -> Permissions {
        self.permissions
    }

    fn end(&self) -> u64 {
        self.base + self.size
    }
}

#[derive(Debug, Clone)]
pub struct AddressSpace {
    page_size: u64,
    regions: BTreeMap<u64, Region>,
}

impl AddressSpace {
    pub fn new(page_size: u64) -> Result<Self, MemoryError> {
        if page_size < DEFAULT_PAGE_SIZE || !page_size.is_power_of_two() {
            return Err(MemoryError::InvalidPageSize(page_size));
        }

        Ok(Self {
            page_size,
            regions: BTreeMap::new(),
        })
    }

    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions.values()
    }

    pub fn merge_disjoint(&mut self, mut other: Self) -> Result<(), MemoryError> {
        if other.page_size != self.page_size {
            return Err(MemoryError::PageSizeMismatch {
                expected: self.page_size,
                actual: other.page_size,
            });
        }

        for region in other.regions.values() {
            self.ensure_available(region.base, region.end())?;
        }

        self.regions.append(&mut other.regions);
        Ok(())
    }

    pub fn map_zeroed(
        &mut self,
        base: u64,
        size: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
        self.require_aligned(base)?;
        self.require_aligned(size)?;
        let end = checked_end(base, size)?;
        self.ensure_available(base, end)?;

        let host_size = usize::try_from(size).map_err(|_| MemoryError::RegionTooLarge(size))?;
        let mut data = Vec::new();
        data.try_reserve_exact(host_size)
            .map_err(|_| MemoryError::AllocationFailed(size))?;
        data.resize(host_size, 0);

        self.regions.insert(
            base,
            Region {
                base,
                size,
                permissions,
                data,
            },
        );
        Ok(())
    }

    pub fn unmap(&mut self, base: u64, size: u64) -> Result<(), MemoryError> {
        let region = self.regions.get(&base).ok_or(MemoryError::NotMapped {
            address: base,
            size,
        })?;
        if region.size != size {
            return Err(MemoryError::RegionSizeMismatch {
                base,
                expected: size,
                actual: region.size,
            });
        }

        self.regions.remove(&base);
        Ok(())
    }

    pub fn protect(
        &mut self,
        base: u64,
        size: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
        let region = self.regions.get_mut(&base).ok_or(MemoryError::NotMapped {
            address: base,
            size,
        })?;
        if region.size != size {
            return Err(MemoryError::RegionSizeMismatch {
                base,
                expected: size,
                actual: region.size,
            });
        }

        region.permissions = permissions;
        Ok(())
    }

    pub fn read(&self, address: u64, size: u64) -> Result<&[u8], MemoryError> {
        let region = self.region_for(address, size)?;
        require_permission(region, address, Permissions::READ)?;
        let start = usize::try_from(address - region.base).expect("mapped offset fits usize");
        let length = usize::try_from(size).expect("mapped size fits usize");
        Ok(&region.data[start..start + length])
    }

    pub fn fetch(&self, address: u64, size: u64) -> Result<&[u8], MemoryError> {
        let region = self.region_for(address, size)?;
        require_permission(region, address, Permissions::EXECUTE)?;
        let start = usize::try_from(address - region.base).expect("mapped offset fits usize");
        let length = usize::try_from(size).expect("mapped size fits usize");
        Ok(&region.data[start..start + length])
    }

    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let size = u64::try_from(bytes.len()).map_err(|_| MemoryError::RegionTooLarge(u64::MAX))?;
        let key = self.region_key_for(address, size)?;
        let region = self.regions.get_mut(&key).expect("located region exists");
        require_permission(region, address, Permissions::WRITE)?;
        let start = usize::try_from(address - region.base).expect("mapped offset fits usize");
        region.data[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn require_aligned(&self, value: u64) -> Result<(), MemoryError> {
        if !value.is_multiple_of(self.page_size) {
            return Err(MemoryError::Unaligned {
                value,
                alignment: self.page_size,
            });
        }
        Ok(())
    }

    fn ensure_available(&self, base: u64, end: u64) -> Result<(), MemoryError> {
        if let Some((existing_base, _)) = self
            .regions
            .range(..=base)
            .next_back()
            .filter(|(_, existing)| existing.end() > base)
        {
            return Err(MemoryError::Overlap {
                base: *existing_base,
            });
        }

        if let Some((existing_base, _)) = self
            .regions
            .range(base..)
            .next()
            .filter(|(existing_base, _)| **existing_base < end)
        {
            return Err(MemoryError::Overlap {
                base: *existing_base,
            });
        }

        Ok(())
    }

    fn region_key_for(&self, address: u64, size: u64) -> Result<u64, MemoryError> {
        let end = checked_end(address, size)?;
        let (base, region) = self
            .regions
            .range(..=address)
            .next_back()
            .ok_or(MemoryError::NotMapped { address, size })?;

        if end > region.end() {
            return Err(MemoryError::NotMapped { address, size });
        }

        Ok(*base)
    }

    fn region_for(&self, address: u64, size: u64) -> Result<&Region, MemoryError> {
        let key = self.region_key_for(address, size)?;
        Ok(self.regions.get(&key).expect("located region exists"))
    }
}

fn checked_end(base: u64, size: u64) -> Result<u64, MemoryError> {
    if size == 0 {
        return Err(MemoryError::ZeroSize);
    }
    base.checked_add(size).ok_or(MemoryError::AddressOverflow)
}

fn require_permission(
    region: &Region,
    address: u64,
    required: Permissions,
) -> Result<(), MemoryError> {
    if !region.permissions.contains(required) {
        return Err(MemoryError::PermissionDenied { address, required });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AddressSpace, MemoryError, Permissions};

    #[test]
    fn maps_sparse_regions_and_enforces_permissions() {
        let mut memory = AddressSpace::new(0x1000).unwrap();
        memory
            .map_zeroed(0x1000, 0x1000, Permissions::READ | Permissions::WRITE)
            .unwrap();
        memory
            .map_zeroed(0x4000, 0x1000, Permissions::READ | Permissions::EXECUTE)
            .unwrap();

        memory.write(0x1010, &[1, 2, 3, 4]).unwrap();
        assert_eq!(memory.read(0x1010, 4).unwrap(), &[1, 2, 3, 4]);
        assert!(matches!(
            memory.write(0x4000, &[1]),
            Err(MemoryError::PermissionDenied { .. })
        ));
        assert_eq!(memory.fetch(0x4000, 1).unwrap(), &[0]);
        assert_eq!(memory.regions().count(), 2);
    }

    #[test]
    fn rejects_overlap_cross_region_access_and_unaligned_maps() {
        let mut memory = AddressSpace::new(0x1000).unwrap();
        memory
            .map_zeroed(0x2000, 0x2000, Permissions::READ)
            .unwrap();

        assert!(matches!(
            memory.map_zeroed(0x3000, 0x1000, Permissions::READ),
            Err(MemoryError::Overlap { .. })
        ));
        assert!(matches!(
            memory.read(0x3fff, 2),
            Err(MemoryError::NotMapped { .. })
        ));
        assert!(matches!(
            memory.map_zeroed(0x5001, 0x1000, Permissions::READ),
            Err(MemoryError::Unaligned { .. })
        ));
    }

    #[test]
    fn protect_and_unmap_require_the_exact_region() {
        let mut memory = AddressSpace::new(0x1000).unwrap();
        memory
            .map_zeroed(0x8000, 0x1000, Permissions::READ | Permissions::WRITE)
            .unwrap();
        memory
            .protect(0x8000, 0x1000, Permissions::READ | Permissions::EXECUTE)
            .unwrap();

        assert!(memory.fetch(0x8000, 1).is_ok());
        assert!(matches!(
            memory.write(0x8000, &[0]),
            Err(MemoryError::PermissionDenied { .. })
        ));
        assert!(matches!(
            memory.unmap(0x8000, 0x2000),
            Err(MemoryError::RegionSizeMismatch { .. })
        ));
        memory.unmap(0x8000, 0x1000).unwrap();
        assert!(memory.read(0x8000, 1).is_err());
    }

    #[test]
    fn merges_disjoint_staged_regions_without_partial_commit() {
        let mut memory = AddressSpace::new(0x1000).unwrap();
        memory
            .map_zeroed(0x1000, 0x1000, Permissions::READ)
            .unwrap();

        let mut staged = AddressSpace::new(0x1000).unwrap();
        staged
            .map_zeroed(0x3000, 0x1000, Permissions::READ)
            .unwrap();
        memory.merge_disjoint(staged).unwrap();
        assert_eq!(memory.regions().count(), 2);

        let mut conflicting = AddressSpace::new(0x1000).unwrap();
        conflicting
            .map_zeroed(0x3000, 0x1000, Permissions::READ)
            .unwrap();
        assert!(matches!(
            memory.merge_disjoint(conflicting),
            Err(MemoryError::Overlap { .. })
        ));
        assert_eq!(memory.regions().count(), 2);

        let other_page_size = AddressSpace::new(0x2000).unwrap();
        assert!(matches!(
            memory.merge_disjoint(other_page_size),
            Err(MemoryError::PageSizeMismatch { .. })
        ));
        assert_eq!(memory.regions().count(), 2);
    }

    #[test]
    fn rejects_invalid_page_sizes_and_overflow() {
        assert!(matches!(
            AddressSpace::new(0),
            Err(MemoryError::InvalidPageSize(0))
        ));

        let mut memory = AddressSpace::new(0x1000).unwrap();
        assert!(matches!(
            memory.map_zeroed(u64::MAX - 0xfff, 0x2000, Permissions::NONE),
            Err(MemoryError::AddressOverflow)
        ));
    }
}
