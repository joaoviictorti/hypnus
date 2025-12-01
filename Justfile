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

# Format all .toml files using Taplo
taplo:
    taplo format