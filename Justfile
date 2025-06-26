# Aliases
alias c := clean
alias up := update

# Use PowerShell shell on Windows
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Clean target
clean:
    cargo clean

# Updates dependencies as per Cargo.toml
update:
    cargo update

# Publishes the crate to crates.io
publish:
    cargo publish --allow-dirty

# Formats all Rust source files
fmt:
    cargo +nightly fmt --check

# Builds local documentation
docs:
    cargo doc --no-deps --open

# Run only integration tests in /tests directory
test:
    cargo test --test '*' -- --nocapture

# Test this workflow on your machine with `act`
act:
    act -P windows-latest=-self-hosted

# Format all .toml files using Taplo
taplo:
    taplo format