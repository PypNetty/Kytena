#!/bin/bash
# scripts/install-trivy.sh
# Script pour installer Trivy sur différentes plateformes

set -e

echo "Installing Trivy vulnerability scanner..."

# Détecter le système d'exploitation
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Mapper l'architecture pour les releases Trivy
case $ARCH in
    x86_64)
        TRIVY_ARCH="64bit"
        ;;
    aarch64|arm64)
        TRIVY_ARCH="ARM64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Installer selon le système d'exploitation
case $OS in
    linux)
        echo "Detected Linux OS"
        
        # Vérifier si on peut utiliser apt
        if command -v apt-get >/dev/null 2>&1; then
            echo "Using apt package manager"
            
            # Configurer le dépôt
            sudo apt-get update
            sudo apt-get install -y wget apt-transport-https gnupg lsb-release
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
            
            # Installer Trivy
            sudo apt-get update
            sudo apt-get install -y trivy
            
        # Vérifier si on peut utiliser yum/dnf
        elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
            echo "Using yum/dnf package manager"
            
            # Configurer le dépôt
            sudo rpm -ivh https://aquasecurity.github.io/trivy-repo/rpm/releases/trivy_0.15.0_Linux-64bit.rpm 2>/dev/null || true
            
            # Installer Trivy
            if command -v dnf >/dev/null 2>&1; then
                sudo dnf -y install trivy
            else
                sudo yum -y install trivy
            fi
            
        # Utiliser le binaire pré-compilé
        else
            echo "Installing pre-compiled binary"
            
            # Télécharger et extraire le binaire
            wget -q https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux-${TRIVY_ARCH}.tar.gz -O trivy.tar.gz
            tar -xf trivy.tar.gz trivy
            rm trivy.tar.gz
            
            # Installer le binaire
            sudo mv trivy /usr/local/bin/
            sudo chmod +x /usr/local/bin/trivy
        fi
        ;;
        
    darwin)
        echo "Detected macOS"
        
        # Vérifier si Homebrew est installé
        if command -v brew >/dev/null 2>&1; then
            echo "Using Homebrew"
            brew install aquasecurity/trivy/trivy
        else
            echo "Installing pre-compiled binary"
            
            # Télécharger et extraire le binaire
            wget -q https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Darwin-${TRIVY_ARCH}.tar.gz -O trivy.tar.gz
            tar -xf trivy.tar.gz trivy
            rm trivy.tar.gz
            
            # Installer le binaire
            sudo mv trivy /usr/local/bin/
            sudo chmod +x /usr/local/bin/trivy
        fi
        ;;
        
    *)
        echo "Unsupported operating system: $OS"
        exit 1
        ;;
esac

# Vérifier que Trivy est bien installé
if command -v trivy >/dev/null 2>&1; then
    echo "Trivy installed successfully!"
    TRIVY_VERSION=$(trivy --version | head -n1)
    echo "$TRIVY_VERSION"
    
    # Initialiser la base de données
    echo "Initializing vulnerability database (this may take a while)..."
    trivy image --download-db-only >/dev/null 2>&1
    echo "Vulnerability database initialized"
else
    echo "Trivy installation failed!"
    exit 1
fi

echo "Trivy is ready to use with Kytena!"

