@echo off
REM Installation script for mjsrecon external tools (Windows)
REM This script helps install the required external tools for the GitHub reconnaissance module

echo 🔧 Installing external tools for mjsrecon GitHub reconnaissance module...

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Go is not installed. Please install Go from https://golang.org/dl/
    echo After installing Go, restart this script.
    pause
    exit /b 1
)

echo ✅ Go is installed

REM Function to check if a command exists
:check_tool
set "tool_name=%~1"
set "install_cmd=%~2"

%tool_name% --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ %tool_name% is already installed
) else (
    echo 📦 Installing %tool_name%...
    %install_cmd%
    %tool_name% --version >nul 2>&1
    if %errorlevel% equ 0 (
        echo ✅ %tool_name% installed successfully
    ) else (
        echo ❌ Failed to install %tool_name%
        echo Please install it manually: %install_cmd%
    )
)
goto :eof

REM Install tools
call :check_tool "trufflehog" "go install github.com/trufflesecurity/trufflehog@latest"
call :check_tool "gitleaks" "go install github.com/gitleaks/gitleaks@latest"
call :check_tool "waybackurls" "go install github.com/tomnomnom/waybackurls@latest"
call :check_tool "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"
call :check_tool "katana" "go install github.com/projectdiscovery/katana/cmd/katana@latest"
call :check_tool "ffuf" "go install github.com/ffuf/ffuf@latest"
call :check_tool "jsluice" "go install github.com/BishopFox/jsluice@latest"

echo.
echo 🐍 Installing Python dependencies...
pip install -r requirements.txt

echo.
echo 🎉 Installation complete!
echo.
echo 📝 Next steps:
echo 1. Set up GitHub API token (optional but recommended):
echo    set GITHUB_TOKEN=your_token_here
echo.
echo 2. Test the installation:
echo    python -m mjsrecon.core github --targets test-org --github-max-repos 1
echo.
echo 3. Check tool availability:
echo    trufflehog --version
echo    gitleaks version
echo.
echo 📚 For more information, see the README.md file
pause 