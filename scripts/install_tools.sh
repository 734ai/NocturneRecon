#!/bin/bash

# NocturneRecon Tool Installation Script
# Installs external tools used by the framework

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "ubuntu"
        elif command_exists yum; then
            echo "rhel"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to install Go if not present
install_go() {
    if command_exists go; then
        print_info "Go is already installed"
        return
    fi
    
    print_info "Installing Go..."
    
    OS=$(detect_os)
    case $OS in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y golang-go
            ;;
        rhel)
            sudo yum install -y golang
            ;;
        arch)
            sudo pacman -S go
            ;;
        macos)
            if command_exists brew; then
                brew install go
            else
                print_error "Please install Go manually from https://golang.org/dl/"
                return 1
            fi
            ;;
        *)
            print_error "Please install Go manually from https://golang.org/dl/"
            return 1
            ;;
    esac
    
    print_success "Go installed successfully"
}

# Function to install Amass
install_amass() {
    if command_exists amass; then
        print_info "Amass is already installed"
        return
    fi
    
    print_info "Installing Amass..."
    
    # Install via Go
    if command_exists go; then
        go install -v github.com/owasp-amass/amass/v4/...@master
        
        # Add Go bin to PATH if not already there
        GOPATH=$(go env GOPATH)
        if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
            echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
            export PATH=$PATH:$GOPATH/bin
        fi
        
        if command_exists amass; then
            print_success "Amass installed successfully"
        else
            print_error "Amass installation failed"
        fi
    else
        print_error "Go is required to install Amass"
        return 1
    fi
}

# Function to install gowitness
install_gowitness() {
    if command_exists gowitness; then
        print_info "gowitness is already installed"
        return
    fi
    
    print_info "Installing gowitness..."
    
    if command_exists go; then
        go install github.com/sensepost/gowitness@latest
        
        if command_exists gowitness; then
            print_success "gowitness installed successfully"
        else
            print_error "gowitness installation failed"
        fi
    else
        print_error "Go is required to install gowitness"
        return 1
    fi
}

# Function to install massdns
install_massdns() {
    if command_exists massdns; then
        print_info "massdns is already installed"
        return
    fi
    
    print_info "Installing massdns..."
    
    # Check if build tools are available
    OS=$(detect_os)
    case $OS in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y build-essential git
            ;;
        rhel)
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y git
            ;;
        arch)
            sudo pacman -S base-devel git
            ;;
        macos)
            if ! command_exists make; then
                print_error "Xcode command line tools required. Run: xcode-select --install"
                return 1
            fi
            ;;
    esac
    
    # Clone and build massdns
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    git clone https://github.com/blechschmidt/massdns.git
    cd massdns
    make
    
    # Install to /usr/local/bin
    sudo cp bin/massdns /usr/local/bin/
    
    # Clean up
    cd /
    rm -rf "$TEMP_DIR"
    
    if command_exists massdns; then
        print_success "massdns installed successfully"
    else
        print_error "massdns installation failed"
    fi
}

# Function to install subfinder
install_subfinder() {
    if command_exists subfinder; then
        print_info "subfinder is already installed"
        return
    fi
    
    print_info "Installing subfinder..."
    
    if command_exists go; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        
        if command_exists subfinder; then
            print_success "subfinder installed successfully"
        else
            print_error "subfinder installation failed"
        fi
    else
        print_error "Go is required to install subfinder"
        return 1
    fi
}

# Function to install system dependencies
install_system_deps() {
    print_info "Installing system dependencies..."
    
    OS=$(detect_os)
    case $OS in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y \
                python3 \
                python3-pip \
                python3-venv \
                curl \
                wget \
                git \
                dnsutils \
                whois \
                nmap \
                chromium-browser \
                firefox
            ;;
        rhel)
            sudo yum install -y \
                python3 \
                python3-pip \
                curl \
                wget \
                git \
                bind-utils \
                whois \
                nmap \
                chromium \
                firefox
            ;;
        arch)
            sudo pacman -S \
                python \
                python-pip \
                curl \
                wget \
                git \
                bind-tools \
                whois \
                nmap \
                chromium \
                firefox
            ;;
        macos)
            if command_exists brew; then
                brew install \
                    python3 \
                    curl \
                    wget \
                    git \
                    bind \
                    whois \
                    nmap
            else
                print_warning "Homebrew not found. Please install system dependencies manually."
            fi
            ;;
        *)
            print_warning "Unknown OS. Please install system dependencies manually."
            ;;
    esac
    
    print_success "System dependencies installation completed"
}

# Function to create directories
create_directories() {
    print_info "Creating directories..."
    
    # Create wordlists directory
    mkdir -p "$HOME/.nocturnerecon/wordlists"
    
    # Create config directory
    mkdir -p "$HOME/.nocturnerecon"
    
    print_success "Directories created"
}

# Function to download wordlists
download_wordlists() {
    print_info "Downloading wordlists..."
    
    WORDLIST_DIR="$HOME/.nocturnerecon/wordlists"
    
    # SecLists subdomains
    if [ ! -f "$WORDLIST_DIR/subdomains-top1million-5000.txt" ]; then
        curl -L -o "$WORDLIST_DIR/subdomains-top1million-5000.txt" \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
    fi
    
    # Common subdomains
    if [ ! -f "$WORDLIST_DIR/common-subdomains.txt" ]; then
        curl -L -o "$WORDLIST_DIR/common-subdomains.txt" \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt"
    fi
    
    print_success "Wordlists downloaded"
}

# Main installation function
main() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                   NocturneRecon Installer                    ║"
    echo "║              Installing external tools and deps              ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Some installations may not work correctly."
    fi
    
    # Detect OS
    OS=$(detect_os)
    print_info "Detected OS: $OS"
    
    # Install system dependencies
    install_system_deps
    
    # Create directories
    create_directories
    
    # Install Go (required for many tools)
    install_go
    
    # Install reconnaissance tools
    install_amass
    install_gowitness
    install_massdns
    install_subfinder
    
    # Download wordlists
    download_wordlists
    
    echo
    print_success "Installation completed!"
    echo
    print_info "Installed tools:"
    echo "  - amass: $(command_exists amass && echo 'YES' || echo 'NO')"
    echo "  - gowitness: $(command_exists gowitness && echo 'YES' || echo 'NO')"
    echo "  - massdns: $(command_exists massdns && echo 'YES' || echo 'NO')"
    echo "  - subfinder: $(command_exists subfinder && echo 'YES' || echo 'NO')"
    echo
    print_info "Next steps:"
    echo "  1. Install Python dependencies: pip install -r requirements.txt"
    echo "  2. Run NocturneRecon: python3 main.py --help"
    echo
    print_info "Configuration files and wordlists are in: $HOME/.nocturnerecon/"
}

# Run main function
main "$@"
