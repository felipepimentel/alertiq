#!/bin/bash

# Set RUST_LOG if not already set
export RUST_LOG=${RUST_LOG:-debug}

# Check if entr is installed
if ! command -v entr &> /dev/null; then
    echo "entr is not installed. Installing..."
    sudo apt-get update && sudo apt-get install -y entr
fi

echo "Starting development server with auto-reload..."
echo "Press Ctrl+C to stop"

# Watch all Rust files and run cargo when they change
find . -name "*.rs" | entr -r cargo run 