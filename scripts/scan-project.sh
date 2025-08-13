#!/bin/bash

PROJECT_PATH="${1:-.}"
ANALYZER_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Started..."
echo "Project path: $(basename "$PROJECT_PATH")"
echo ""

# Check if project path exists
if [ ! -d "$PROJECT_PATH" ]; then
    echo "Error: Project path '$PROJECT_PATH' not found"
    exit 1
fi

# Navigate to project
cd "$PROJECT_PATH"

# Check if it's a Rust project
if [ ! -f "Cargo.toml" ]; then
    echo "Error: No Cargo.toml found. This doesn't appear to be a Rust project."
    exit 1
fi

echo "Creating CodeQL db"
if codeql database create sealevel-security-db \
    --language=rust \
    --source-root=. \
    --command="cargo check" \
    --overwrite \
    --quiet; then

    echo ""
    echo "DB created successfully"
    echo ""
    
    echo "Running Sealevel attack pattern analysis..."
    
    if codeql database analyze sealevel-security-db \
        "$ANALYZER_ROOT/queries/SealevelSecurityAnalyzer.ql" \
        --format=sarif-latest \
        --output="sealevel-vulnerabilities.sarif" \
        --quiet; then
        
        # Count findings
        findings=$(jq '.runs[0].results | length' sealevel-vulnerabilities.sarif 2>/dev/null || echo "0")
        
        echo ""
        echo "SEALEVEL SECURITY ANALYSIS"
        
        if [ "$findings" -gt 0 ]; then
            echo " Found $findings Sealevel vulnerability patterns:"
            echo ""
            
            # Show detailed findings
            jq -r '.runs[0].results[] | 
                " " + .message.text + 
                "\n   Location: " + .locations[0].physicalLocation.artifactLocation.uri + 
                ":" + (.locations[0].physicalLocation.region.startLine | tostring) +
                "\n"' sealevel-vulnerabilities.sarif 2>/dev/null
            
            echo ""
            echo "Full SARIF report: $(pwd)/sealevel-vulnerabilities.sarif"
            
        else
            echo "DONE! No Sealevel attack patterns detected!"
        fi
        
    else
        echo "Error: Sealevel analysis failed"
        exit 1
    fi
    
else
    echo "Error: Failed to create CodeQL database"
    echo ""
    exit 1
fi

echo ""
echo "Done!"

if [ "$findings" -gt 0 ]; then
    exit 1
fi