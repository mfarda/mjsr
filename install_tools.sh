#!/bin/bash

# Installation script for mjsrecon external tools
# This script helps install the required external tools for the GitHub reconnaissance module

echo "🔧 Installing external tools for mjsrecon GitHub reconnaissance module..."

# Check if we're on a supported platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
else
    echo "❌ Unsupported platform: $OSTYPE"
    echo "Please install tools manually or use a supported platform (Linux/macOS)"
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install tool with confirmation
install_tool() {
    local tool_name=$1
    local install_cmd=$2
    
    if command_exists "$tool_name"; then
        echo "✅ $tool_name is already installed"
    else
        echo "📦 Installing $tool_name..."
        eval "$install_cmd"
        if command_exists "$tool_name"; then
            echo "✅ $tool_name installed successfully"
        else
            echo "❌ Failed to install $tool_name"
            echo "Please install it manually: $install_cmd"
        fi
    fi
}

# Install Go (required for many tools)
if ! command_exists go; then
    echo "📦 Installing Go..."
    if [[ "$PLATFORM" == "linux" ]]; then
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        source ~/.bashrc
        rm go1.21.0.linux-amd64.tar.gz
    elif [[ "$PLATFORM" == "macos" ]]; then
        brew install go
    fi
fi

# Install TruffleHog
install_tool "trufflehog" "go install github.com/trufflesecurity/trufflehog@latest"

# Install GitLeaks
install_tool "gitleaks" "go install github.com/gitleaks/gitleaks@latest"

# Install other required tools
echo ""
echo "📋 Installing other required tools..."

# Install waybackurls
install_tool "waybackurls" "go install github.com/tomnomnom/waybackurls@latest"

# Install gau
install_tool "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"

# Install katana
install_tool "katana" "go install github.com/projectdiscovery/katana/cmd/katana@latest"

# Install ffuf
install_tool "ffuf" "go install github.com/ffuf/ffuf@latest"

# Install jsluice
install_tool "jsluice" "go install github.com/BishopFox/jsluice@latest"

# Install Python dependencies
echo ""
echo "🐍 Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📝 Next steps:"
echo "1. Set up GitHub API token (optional but recommended):"
echo "   export GITHUB_TOKEN=your_token_here"
echo ""
echo "2. Test the installation:"
echo "   python -m mjsrecon.core github --targets test-org --github-max-repos 1"
echo ""
echo "3. Check tool availability:"
echo "   trufflehog --version"
echo "   gitleaks version"
echo ""
echo "📚 For more information, see the README.md file" 