#!/bin/bash

echo "Installing CodeQL dependencies..."
set -e

# Change to queries directory
cd "$(dirname "$0")/../queries"

codeql pack install

echo "Dependencies installed successfully!"