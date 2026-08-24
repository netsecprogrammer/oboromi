use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const PROFILE_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROFILE_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_PROGRAMS: usize = 16_384;
pub const MAX_SERVICES: usize = 65_536;
pub const MAX_PROGRAM_ENTRIES: usize = 4_096;
pub const MAX_SERVICE_NAME_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Switch,
    Switch2,
    Synthetic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Verified,
    Inferred,
    Synthetic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source_sha256: String,
    pub extraction_tool: String,
    pub extraction_tool_version: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HardwareProfile {
    pub core_count: u16,
    pub memory_size: u64,
    pub page_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProgramProfile {
    pub program_id: String,
    pub build_id: Option<String>,
    pub capabilities: Vec<String>,
    pub client_services: Vec<String>,
    pub server_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceProfile {
    pub name: String,
    pub owner_program_id: String,
    pub minimum_firmware: Option<String>,
    pub maximum_firmware: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirmwareProfile {
    pub schema_version: u32,
    pub platform: Platform,
    pub firmware_version: String,
    pub provenance: Provenance,
    pub hardware: HardwareProfile,
    pub programs: Vec<ProgramProfile>,
    pub services: Vec<ServiceProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    UnsupportedSchema(u32),
    ProfileTooLarge {
        actual: usize,
        maximum: usize,
    },
    TooManyEntries {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    InvalidTextField(&'static str),
    InvalidFirmwareVersion(&'static str),
    InvalidFirmwareBounds {
        service_name: String,
        minimum: String,
        maximum: String,
    },
    InvalidSha256,
    InconsistentProvenance,
    InvalidCoreCount(u16),
    InvalidPageSize(u64),
    InvalidMemorySize(u64),
    InvalidProgramId(String),
    InvalidBuildId(String),
    DuplicateProgramId(String),
    InvalidServiceName(String),
    DuplicateServiceName(String),
    UnknownOwner(String),
    DuplicateServiceReference {
        program_id: String,
        service_name: String,
        relationship: &'static str,
    },
    UnknownServiceReference {
        program_id: String,
        service_name: String,
    },
    ServiceOwnerMismatch {
        service_name: String,
        owner_program_id: String,
        server_program_id: String,
    },
    MissingServerDeclaration {
        service_name: String,
        owner_program_id: String,
    },
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema(version) => {
                write!(f, "unsupported firmware profile schema version {version}")
            }
            Self::ProfileTooLarge { actual, maximum } => write!(
                f,
                "firmware profile is {actual} bytes; maximum is {maximum} bytes",
            ),
            Self::TooManyEntries {
                field,
                actual,
                maximum,
            } => write!(
                f,
                "firmware profile field {field} contains {actual} entries; maximum is {maximum}",
            ),
            Self::InvalidTextField(field) => {
                write!(f, "firmware profile field {field} contains invalid text")
            }
            Self::InvalidFirmwareVersion(field) => write!(
                f,
                "firmware profile field {field} must use canonical MAJOR.MINOR.PATCH syntax",
            ),
            Self::InvalidFirmwareBounds {
                service_name,
                minimum,
                maximum,
            } => write!(
                f,
                "service {service_name:?} has minimum firmware {minimum:?} above maximum {maximum:?}",
            ),
            Self::InvalidSha256 => write!(f, "source_sha256 must contain 64 hexadecimal digits"),
            Self::InconsistentProvenance => {
                write!(f, "synthetic confidence must match a synthetic platform",)
            }
            Self::InvalidCoreCount(count) => write!(f, "invalid core count {count}"),
            Self::InvalidPageSize(size) => write!(f, "invalid page size {size:#x}"),
            Self::InvalidMemorySize(size) => write!(f, "invalid memory size {size:#x}"),
            Self::InvalidProgramId(id) => write!(f, "invalid program id {id:?}"),
            Self::InvalidBuildId(id) => write!(f, "invalid build id {id:?}"),
            Self::DuplicateProgramId(id) => write!(f, "duplicate program id {id:?}"),
            Self::InvalidServiceName(name) => write!(f, "invalid service name {name:?}"),
            Self::DuplicateServiceName(name) => write!(f, "duplicate service name {name:?}"),
            Self::UnknownOwner(id) => write!(f, "service owner {id:?} is not in the profile"),
            Self::DuplicateServiceReference {
                program_id,
                service_name,
                relationship,
            } => write!(
                f,
                "program {program_id:?} declares {relationship} service {service_name:?} more than once"
            ),
            Self::UnknownServiceReference {
                program_id,
                service_name,
            } => write!(
                f,
                "program {program_id:?} references unknown service {service_name:?}"
            ),
            Self::ServiceOwnerMismatch {
                service_name,
                owner_program_id,
                server_program_id,
            } => write!(
                f,
                "service {service_name} is owned by {owner_program_id}, not server {server_program_id}"
            ),
            Self::MissingServerDeclaration {
                service_name,
                owner_program_id,
            } => write!(
                f,
                "service {service_name} is owned by {owner_program_id} but is absent from that program's server_services"
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

#[derive(Debug)]
pub enum ProfileLoadError {
    Json(serde_json::Error),
    Validation(ProfileError),
}

impl std::fmt::Display for ProfileLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => write!(f, "invalid firmware profile JSON: {error}"),
            Self::Validation(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ProfileLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Validation(error) => Some(error),
        }
    }
}

impl FirmwareProfile {
    pub fn from_json(data: &[u8]) -> Result<Self, ProfileLoadError> {
        if data.len() > MAX_PROFILE_SIZE {
            return Err(ProfileLoadError::Validation(
                ProfileError::ProfileTooLarge {
                    actual: data.len(),
                    maximum: MAX_PROFILE_SIZE,
                },
            ));
        }
        let profile: Self = serde_json::from_slice(data).map_err(ProfileLoadError::Json)?;
        profile.validate().map_err(ProfileLoadError::Validation)?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(ProfileError::UnsupportedSchema(self.schema_version));
        }
        validate_text("firmware_version", &self.firmware_version, 128)?;
        if self.platform != Platform::Synthetic
            && parse_firmware_version(&self.firmware_version).is_none()
        {
            return Err(ProfileError::InvalidFirmwareVersion("firmware_version"));
        }
        validate_text("extraction_tool", &self.provenance.extraction_tool, 256)?;
        validate_text(
            "extraction_tool_version",
            &self.provenance.extraction_tool_version,
            128,
        )?;
        if !is_lower_hex(&self.provenance.source_sha256, 64, false) {
            return Err(ProfileError::InvalidSha256);
        }
        validate_count("programs", self.programs.len(), MAX_PROGRAMS)?;
        validate_count("services", self.services.len(), MAX_SERVICES)?;
        let provenance_is_consistent = match self.platform {
            Platform::Synthetic => self.provenance.confidence == Confidence::Synthetic,
            Platform::Switch | Platform::Switch2 => {
                self.provenance.confidence != Confidence::Synthetic
            }
        };
        if !provenance_is_consistent {
            return Err(ProfileError::InconsistentProvenance);
        }

        if self.hardware.core_count == 0 || self.hardware.core_count > 256 {
            return Err(ProfileError::InvalidCoreCount(self.hardware.core_count));
        }
        if self.hardware.page_size < 0x1000 || !self.hardware.page_size.is_power_of_two() {
            return Err(ProfileError::InvalidPageSize(self.hardware.page_size));
        }
        if self.hardware.memory_size == 0
            || !self
                .hardware
                .memory_size
                .is_multiple_of(self.hardware.page_size)
        {
            return Err(ProfileError::InvalidMemorySize(self.hardware.memory_size));
        }

        let mut program_ids = HashSet::new();
        for program in &self.programs {
            validate_count(
                "program.capabilities",
                program.capabilities.len(),
                MAX_PROGRAM_ENTRIES,
            )?;
            validate_count(
                "program.client_services",
                program.client_services.len(),
                MAX_PROGRAM_ENTRIES,
            )?;
            validate_count(
                "program.server_services",
                program.server_services.len(),
                MAX_PROGRAM_ENTRIES,
            )?;
            for capability in &program.capabilities {
                validate_text("program.capability", capability, 256)?;
            }
            let Some(program_id) = parse_program_id(&program.program_id) else {
                return Err(ProfileError::InvalidProgramId(program.program_id.clone()));
            };
            if let Some(build_id) = program
                .build_id
                .as_ref()
                .filter(|build_id| !is_lower_hex(build_id, 64, false))
            {
                return Err(ProfileError::InvalidBuildId(build_id.clone()));
            }
            if !program_ids.insert(program_id) {
                return Err(ProfileError::DuplicateProgramId(program.program_id.clone()));
            }
        }

        let mut services_by_name = HashMap::new();
        for service in &self.services {
            if service.name.is_empty()
                || service.name.trim() != service.name
                || service.name.len() > MAX_SERVICE_NAME_BYTES
                || !service
                    .name
                    .bytes()
                    .all(|byte| (0x20..0x7f).contains(&byte))
            {
                return Err(ProfileError::InvalidServiceName(service.name.clone()));
            }
            let minimum = service
                .minimum_firmware
                .as_deref()
                .map(|value| {
                    validate_text("minimum_firmware", value, 128)?;
                    let version = parse_firmware_version(value)
                        .ok_or(ProfileError::InvalidFirmwareVersion("minimum_firmware"))?;
                    Ok((version, value))
                })
                .transpose()?;
            let maximum = service
                .maximum_firmware
                .as_deref()
                .map(|value| {
                    validate_text("maximum_firmware", value, 128)?;
                    let version = parse_firmware_version(value)
                        .ok_or(ProfileError::InvalidFirmwareVersion("maximum_firmware"))?;
                    Ok((version, value))
                })
                .transpose()?;
            if let (Some((minimum_version, minimum)), Some((maximum_version, maximum))) =
                (minimum, maximum)
                && minimum_version > maximum_version
            {
                return Err(ProfileError::InvalidFirmwareBounds {
                    service_name: service.name.clone(),
                    minimum: minimum.to_string(),
                    maximum: maximum.to_string(),
                });
            }
            if services_by_name
                .insert(service.name.as_str(), service)
                .is_some()
            {
                return Err(ProfileError::DuplicateServiceName(service.name.clone()));
            }
            let Some(owner_program_id) = parse_program_id(&service.owner_program_id) else {
                return Err(ProfileError::InvalidProgramId(
                    service.owner_program_id.clone(),
                ));
            };
            if !program_ids.contains(&owner_program_id) {
                return Err(ProfileError::UnknownOwner(service.owner_program_id.clone()));
            }
        }

        let mut server_declarations = HashSet::new();
        for program in &self.programs {
            let program_id = parse_program_id(&program.program_id)
                .expect("program IDs were validated in the first pass");

            let mut client_services = HashSet::new();
            for service_name in &program.client_services {
                if !client_services.insert(service_name.as_str()) {
                    return Err(ProfileError::DuplicateServiceReference {
                        program_id: program.program_id.clone(),
                        service_name: service_name.clone(),
                        relationship: "client",
                    });
                }
                if !services_by_name.contains_key(service_name.as_str()) {
                    return Err(ProfileError::UnknownServiceReference {
                        program_id: program.program_id.clone(),
                        service_name: service_name.clone(),
                    });
                }
            }

            let mut server_services = HashSet::new();
            for service_name in &program.server_services {
                if !server_services.insert(service_name.as_str()) {
                    return Err(ProfileError::DuplicateServiceReference {
                        program_id: program.program_id.clone(),
                        service_name: service_name.clone(),
                        relationship: "server",
                    });
                }
                let service = services_by_name.get(service_name.as_str()).ok_or_else(|| {
                    ProfileError::UnknownServiceReference {
                        program_id: program.program_id.clone(),
                        service_name: service_name.clone(),
                    }
                })?;
                let owner_program_id = parse_program_id(&service.owner_program_id)
                    .expect("service owner IDs were validated in the second pass");
                if owner_program_id != program_id {
                    return Err(ProfileError::ServiceOwnerMismatch {
                        service_name: service_name.clone(),
                        owner_program_id: service.owner_program_id.clone(),
                        server_program_id: program.program_id.clone(),
                    });
                }
                server_declarations.insert((program_id, service_name.as_str()));
            }
        }

        for service in &self.services {
            let owner_program_id = parse_program_id(&service.owner_program_id)
                .expect("service owner IDs were validated in the second pass");
            if !server_declarations.contains(&(owner_program_id, service.name.as_str())) {
                return Err(ProfileError::MissingServerDeclaration {
                    service_name: service.name.clone(),
                    owner_program_id: service.owner_program_id.clone(),
                });
            }
        }

        Ok(())
    }
}

fn validate_count(field: &'static str, actual: usize, maximum: usize) -> Result<(), ProfileError> {
    if actual > maximum {
        return Err(ProfileError::TooManyEntries {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ProfileError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > maximum_bytes
        || value.chars().any(char::is_control)
    {
        return Err(ProfileError::InvalidTextField(field));
    }
    Ok(())
}

fn parse_firmware_version(value: &str) -> Option<(u32, u32, u32)> {
    fn component(value: &str) -> Option<u32> {
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        value.parse().ok()
    }

    let mut components = value.split('.');
    let version = (
        component(components.next()?)?,
        component(components.next()?)?,
        component(components.next()?)?,
    );
    if components.next().is_some() {
        return None;
    }
    Some(version)
}

fn parse_program_id(value: &str) -> Option<u64> {
    if !is_lower_hex(value, 16, true) {
        return None;
    }
    u64::from_str_radix(value.strip_prefix("0x")?, 16).ok()
}

fn is_lower_hex(value: &str, digits: usize, prefix: bool) -> bool {
    let value = if prefix {
        match value.strip_prefix("0x") {
            Some(value) => value,
            None => return false,
        }
    } else {
        value
    };

    value.len() == digits
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{FirmwareProfile, Platform, ProfileError, ProfileLoadError};

    const VALID_PROFILE: &str = r#"{
        "schema_version": 1,
        "platform": "synthetic",
        "firmware_version": "test-1",
        "provenance": {
            "source_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "extraction_tool": "oboromi-test",
            "extraction_tool_version": "1.0",
            "confidence": "synthetic"
        },
        "hardware": {
            "core_count": 8,
            "memory_size": 134217728,
            "page_size": 4096
        },
        "programs": [{
            "program_id": "0x0100000000000001",
            "build_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "capabilities": ["svc:1"],
            "client_services": ["bsd:u"],
            "server_services": ["bsd:u"]
        }],
        "services": [{
            "name": "bsd:u",
            "owner_program_id": "0x0100000000000001",
            "minimum_firmware": null,
            "maximum_firmware": null
        }]
    }"#;

    #[test]
    fn loads_and_validates_a_versioned_synthetic_profile() {
        let profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();

        assert_eq!(profile.platform, Platform::Synthetic);
        assert_eq!(profile.programs.len(), 1);
        assert_eq!(profile.services[0].name, "bsd:u");
    }

    #[test]
    fn rejects_unknown_fields_instead_of_guessing() {
        let invalid = VALID_PROFILE.replace(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"switch2_assumption\": true,",
        );

        assert!(matches!(
            FirmwareProfile::from_json(invalid.as_bytes()),
            Err(ProfileLoadError::Json(_))
        ));
    }

    #[test]
    fn keeps_switch_and_switch2_profiles_explicitly_distinct() {
        let switch = VALID_PROFILE
            .replace("\"platform\": \"synthetic\"", "\"platform\": \"switch\"")
            .replace(
                "\"confidence\": \"synthetic\"",
                "\"confidence\": \"inferred\"",
            )
            .replace(
                "\"firmware_version\": \"test-1\"",
                "\"firmware_version\": \"22.5.0\"",
            );
        let switch2 = VALID_PROFILE
            .replace("\"platform\": \"synthetic\"", "\"platform\": \"switch2\"")
            .replace(
                "\"confidence\": \"synthetic\"",
                "\"confidence\": \"inferred\"",
            )
            .replace(
                "\"firmware_version\": \"test-1\"",
                "\"firmware_version\": \"22.5.0\"",
            );

        assert_eq!(
            FirmwareProfile::from_json(switch.as_bytes())
                .unwrap()
                .platform,
            Platform::Switch
        );
        assert_eq!(
            FirmwareProfile::from_json(switch2.as_bytes())
                .unwrap()
                .platform,
            Platform::Switch2
        );
    }

    #[test]
    fn rejects_synthetic_confidence_for_hardware_profiles() {
        let invalid = VALID_PROFILE
            .replace("\"platform\": \"synthetic\"", "\"platform\": \"switch2\"")
            .replace(
                "\"firmware_version\": \"test-1\"",
                "\"firmware_version\": \"22.5.0\"",
            );

        assert!(matches!(
            FirmwareProfile::from_json(invalid.as_bytes()),
            Err(ProfileLoadError::Validation(
                ProfileError::InconsistentProvenance
            ))
        ));
    }

    #[test]
    fn documented_synthetic_fixture_is_valid() {
        let profile = FirmwareProfile::from_json(include_bytes!(
            "../../../examples/firmware-profile.synthetic.json"
        ))
        .unwrap();

        assert_eq!(profile.platform, Platform::Synthetic);
        assert_eq!(profile.hardware.memory_size, 12 * 1024 * 1024 * 1024);
    }

    #[test]
    fn rejects_duplicate_programs_and_unknown_service_owners() {
        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.programs.push(profile.programs[0].clone());
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::DuplicateProgramId(_))
        ));

        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.services[0].owner_program_id = "0x0100000000009999".to_string();
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::UnknownOwner(_))
        ));
    }

    #[test]
    fn rejects_oversized_and_incomplete_profiles() {
        let oversized = vec![b' '; super::MAX_PROFILE_SIZE + 1];
        assert!(matches!(
            FirmwareProfile::from_json(&oversized),
            Err(ProfileLoadError::Validation(
                ProfileError::ProfileTooLarge { .. }
            ))
        ));

        let incomplete = VALID_PROFILE
            .replace("\"programs\": [{", "\"omitted_programs\": [{")
            .replace("\"services\": [{", "\"omitted_services\": [{");
        assert!(matches!(
            FirmwareProfile::from_json(incomplete.as_bytes()),
            Err(ProfileLoadError::Json(_))
        ));
    }

    #[test]
    fn rejects_noncanonical_ids_and_invalid_firmware_bounds() {
        let uppercase = VALID_PROFILE.replace("0x0100000000000001", "0x01000000000000AB");
        assert!(matches!(
            FirmwareProfile::from_json(uppercase.as_bytes()),
            Err(ProfileLoadError::Validation(
                ProfileError::InvalidProgramId(_)
            ))
        ));

        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.services[0].minimum_firmware = Some("\n".to_string());
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::InvalidTextField("minimum_firmware"))
        ));

        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.services[0].minimum_firmware = Some("01.0.0".to_string());
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::InvalidFirmwareVersion("minimum_firmware"))
        ));

        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.services[0].minimum_firmware = Some("2.0.0".to_string());
        profile.services[0].maximum_firmware = Some("1.9.9".to_string());
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::InvalidFirmwareBounds { .. })
        ));
    }

    #[test]
    fn enforces_the_eight_byte_service_manager_name_limit() {
        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.services[0].name = "12345678".to_string();
        profile.programs[0].client_services = vec!["12345678".to_string()];
        profile.programs[0].server_services = vec!["12345678".to_string()];
        profile.validate().unwrap();

        profile.services[0].name.push('9');
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::InvalidServiceName(_))
        ));
    }
    #[test]
    fn rejects_missing_or_duplicate_service_references() {
        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.programs[0].client_services = vec!["missing:u".to_string()];
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::UnknownServiceReference { .. })
        ));

        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.programs[0]
            .server_services
            .push("bsd:u".to_string());
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::DuplicateServiceReference {
                relationship: "server",
                ..
            })
        ));

        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        profile.programs[0].server_services.clear();
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::MissingServerDeclaration { .. })
        ));
    }

    #[test]
    fn rejects_server_declarations_by_non_owners() {
        let mut profile = FirmwareProfile::from_json(VALID_PROFILE.as_bytes()).unwrap();
        let mut wrong_server = profile.programs[0].clone();
        wrong_server.program_id = "0x0100000000000002".to_string();
        wrong_server.client_services.clear();
        profile.programs[0].server_services.clear();
        profile.programs.push(wrong_server);

        assert!(matches!(
            profile.validate(),
            Err(ProfileError::ServiceOwnerMismatch { .. })
        ));
    }
}
