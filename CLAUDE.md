no backward compatibility at all or any legacy code path since it is still pre-release software.
keep package.metadata.ptransfer-protocol-version in Cargo.toml set to the exact ptransfer version whose protocol this program implements, and update it whenever compatibility changes.
run commands with --all-features by default to ensure all code paths are covered.
run cargo clippy --all-features to lint all code paths after rust code changes.
no cargo fmt
