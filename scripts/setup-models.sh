#!/usr/bin/env bash
#
# Download and prepare detector models for offline use.
# Sets up models for PIGuard and LLMGuard detection engines.
#
# Usage: ./scripts/setup-models.sh [--force] [--models-dir DIR]
#

set -euo pipefail

# Configuration
DEFAULT_MODELS_DIR=".models"
MODELS_DIR="${MODELS_DIR:-$DEFAULT_MODELS_DIR}"
FORCE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Model configurations
# Format: "name|huggingface_repo|size_mb"
MODELS=(
    "piguard|ProtectAI/deberta-v3-base-prompt-injection-v2|500"
    "llmguard-injection|protectai/deberta-v3-base-prompt-injection|500"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE=true
            shift
            ;;
        --models-dir)
            MODELS_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--force] [--models-dir DIR]"
            echo ""
            echo "Download and prepare detector models."
            echo ""
            echo "Options:"
            echo "  --force         Re-download models even if they exist"
            echo "  --models-dir    Directory to store models (default: .models)"
            echo "  -h, --help      Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  MODELS_DIR      Alternative to --models-dir"
            echo "  HF_TOKEN        Hugging Face token for gated models"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo "=== Detector Model Setup ==="
echo ""
echo "Models directory: $MODELS_DIR"
echo ""

# Create models directory
mkdir -p "$MODELS_DIR"

# Check for required tools
check_requirements() {
    local missing=()

    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi

    if ! python3 -c "import huggingface_hub" 2>/dev/null; then
        missing+=("huggingface_hub (pip install huggingface_hub)")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Missing requirements:${NC}"
        for req in "${missing[@]}"; do
            echo "  - $req"
        done
        echo ""
        echo "Install with: pip install huggingface_hub"
        exit 1
    fi
}

# Download a model from Hugging Face
download_model() {
    local name="$1"
    local repo="$2"
    local size_mb="$3"
    local model_path="$MODELS_DIR/$name"

    echo -e "${BLUE}=== $name ===${NC}"
    echo "  Repository: $repo"
    echo "  Size: ~${size_mb}MB"

    # Check if already exists
    if [[ -d "$model_path" ]] && [[ "$FORCE" == "false" ]]; then
        echo -e "  ${GREEN}Already exists, skipping${NC}"
        echo "  (Use --force to re-download)"
        return 0
    fi

    echo -e "  ${YELLOW}Downloading...${NC}"

    # Use huggingface_hub to download
    python3 -c "
from huggingface_hub import snapshot_download
import os

repo_id = '$repo'
local_dir = '$model_path'

try:
    snapshot_download(
        repo_id=repo_id,
        local_dir=local_dir,
        local_dir_use_symlinks=False,
        token=os.environ.get('HF_TOKEN'),
    )
    print('  Download complete')
except Exception as e:
    print(f'  Error: {e}')
    exit(1)
"

    if [[ $? -eq 0 ]]; then
        echo -e "  ${GREEN}✓ Downloaded successfully${NC}"
    else
        echo -e "  ${RED}✗ Download failed${NC}"
        return 1
    fi
}

# Verify a downloaded model
verify_model() {
    local name="$1"
    local model_path="$MODELS_DIR/$name"

    if [[ ! -d "$model_path" ]]; then
        echo -e "  ${RED}✗ Not found${NC}"
        return 1
    fi

    # Check for key files
    local required_files=("config.json")
    local missing=()

    for file in "${required_files[@]}"; do
        if [[ ! -f "$model_path/$file" ]]; then
            missing+=("$file")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "  ${RED}✗ Missing files: ${missing[*]}${NC}"
        return 1
    fi

    # Get directory size
    local size
    size=$(du -sh "$model_path" 2>/dev/null | cut -f1)
    echo -e "  ${GREEN}✓ Valid ($size)${NC}"
    return 0
}

# Main execution
echo "Checking requirements..."
check_requirements
echo -e "${GREEN}✓ All requirements met${NC}"
echo ""

echo "Downloading models..."
echo ""

download_count=0
error_count=0

for model_spec in "${MODELS[@]}"; do
    IFS='|' read -r name repo size_mb <<< "$model_spec"

    if download_model "$name" "$repo" "$size_mb"; then
        ((download_count++))
    else
        ((error_count++))
    fi
    echo ""
done

echo "=== Verifying Models ==="
echo ""

for model_spec in "${MODELS[@]}"; do
    IFS='|' read -r name repo size_mb <<< "$model_spec"
    echo "$name:"
    verify_model "$name" || true
done

echo ""
echo "=== Setup Complete ==="
echo ""

if [[ $error_count -eq 0 ]]; then
    echo -e "${GREEN}All models ready!${NC}"
    echo ""
    echo "Models are stored in: $MODELS_DIR"
    echo ""
    echo "To use models, set environment variable:"
    echo "  export REBUFF_MODELS_DIR=$MODELS_DIR"
else
    echo -e "${YELLOW}$error_count model(s) had errors.${NC}"
    echo "Some detectors may run in stub mode."
fi

echo ""
echo "Disk usage:"
du -sh "$MODELS_DIR" 2>/dev/null || echo "  (unable to calculate)"
