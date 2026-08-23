# parser fuzzing

Run the parser targets from this directory with a nightly Rust toolchain and cargo-fuzz:

    cargo +nightly fuzz run hipc_header
    cargo +nightly fuzz run nso_parser

`hipc_header` feeds arbitrary byte slices to the HIPC header and message parsers.

`nso_parser` uses a 1 MiB section limit so malformed inputs cannot make each fuzz iteration allocate hundreds of megabytes.

CI only checks that both targets build from the committed lockfile. Use the commands above to run them.
