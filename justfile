# Show available recipes
default:
    @just --list

# Build and run the app, forwarding args to the CLI (e.g. `just run sign --help`)
run *args:
    cargo run -- {{args}}

# Run the test suite
test:
    cargo test

# Verify formatting, lints (warnings denied), and compilation
check:
    cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo check
