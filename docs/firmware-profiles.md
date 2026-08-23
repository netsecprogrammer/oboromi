# firmware profiles and NSO loading

`FirmwareProfile` loads hardware and firmware metadata from versioned JSON. A profile can target `switch`, `switch2`, or `synthetic` data used by tests.

The profile code does not decrypt firmware or manage keys.

## profile format

Schema version 1 records:

- the platform and firmware version;
- source SHA-256, extraction tool/version, and evidence confidence;
- CPU count, memory size, and page size;
- program IDs, optional NSO build IDs, capabilities, and service relationships;
- service ownership and optional firmware-version bounds.

Profiles are limited to 8 MiB and every collection has its own limit. Programs, capabilities, and services must be present even when they are empty. IDs and hashes use their canonical lowercase forms, and references must point to declared programs and services.

Hardware versions and service bounds use `MAJOR.MINOR.PATCH`; a minimum cannot be greater than its maximum. Service names are limited to the eight-byte Horizon SM representation documented by [libnx](https://github.com/switchbrew/libnx/blob/master/nx/include/switch/services/sm.h#L13-L16).

`synthetic` profiles must use synthetic confidence. Hardware profiles use `verified` or `inferred`. This is only a consistency check; it does not authenticate where a profile came from.

See [the synthetic example](../examples/firmware-profile.synthetic.json). Load and validate it with:

```rust
use oboromi_core::firmware::FirmwareProfile;

let bytes = std::fs::read("examples/firmware-profile.synthetic.json").unwrap();
let profile = FirmwareProfile::from_json(&bytes).unwrap();
```

## NSO loader

`NsoImage::parse` checks the header, section ranges, overlap, decompressed sizes, and optional SHA-256 hashes before returning an image. Sections and the whole image are each limited to 512 MiB. Data-section limits include BSS.

`NsoImage::map_into` prepares mappings in a temporary address space, then merges them after every section succeeds. Text is read/execute, read-only data is read-only, and data plus BSS is read/write. A failed map leaves the destination unchanged.

The header field layout follows the public [switchbrew switch-tools NSO writer](https://github.com/switchbrew/switch-tools/blob/master/src/elf2nso.c).

## not implemented

This is not a firmware boot path. It does not provide:

- container/partition discovery or ExeFS/PFS0 loading;
- relocations, MOD0/dynamic linking, or process capability enforcement;
- kernel scheduling, syscall semantics, or production service implementations;
- firmware decryption or key handling.

Do not commit keys or extracted firmware.
