#!/bin/bash
# Pythia - Interactive Deployment Script
# Helps users choose between production and testing environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Print banner
echo ""
echo "========================================"
echo "  Pythia - SQL Injection Scanner"
echo "  Docker Deployment Helper"
echo "========================================"
echo ""

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not available. Please install Docker Compose."
    exit 1
fi

print_success "Docker and Docker Compose are available"
echo ""

# Ask user what they want to deploy
echo "What would you like to do?"
echo ""
echo "  1) Build Pythia Scanner (for scanning external sites)"
echo "  2) Start Testing Lab (vulnerable apps: DVWA, PHP, Flask)"
echo "  3) Build Scanner + Start Testing Lab"
echo "  4) Stop all services"
echo "  5) Remove all containers and data (reset)"
echo ""
read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        print_info "Building Pythia Scanner..."
        echo ""

        cd "$(dirname "$0")"
        mkdir -p ./data ./reports

        docker compose build

        echo ""
        print_success "Pythia Scanner built successfully!"
        echo ""
        print_info "Usage (run from docker/ directory):"
        echo ""
        echo "  # Scan from host (recommended):"
        echo "  cd .. && python -m pyth --target http://example.com --safe --html"
        echo ""
        echo "  # Or use Docker:"
        echo "  docker compose run --rm pyth --target http://example.com --safe --html"
        echo ""
        print_info "Reports saved to: docker/reports/ (Docker auto-detection)"
        print_info "Database: docker/data/argos.db (Docker auto-detection)"
        ;;

    2)
        print_warning "WARNING: The testing lab is INTENTIONALLY VULNERABLE!"
        print_warning "DO NOT expose it to the public internet!"
        echo ""
        read -p "Do you understand and want to continue? (yes/no): " confirm

        if [ "$confirm" != "yes" ]; then
            print_info "Deployment cancelled."
            exit 0
        fi

        print_info "Starting Testing Lab (Vulnerable Applications)..."
        echo ""

        cd "$(dirname "$0")"
        mkdir -p ./data ./reports

        docker compose -f compose.testing.yml up -d

        echo ""
        print_success "Testing Lab deployed successfully!"
        echo ""
        print_info "Vulnerable applications available at:"
        echo "  - DVWA: http://localhost:8080 (from host)"
        echo "  - PHP App: http://localhost:8081 (from host)"
        echo "  - Flask App: http://localhost:8082 (from host)"
        echo ""
        print_info "Initial setup may take 60-90 seconds..."
        echo ""
        print_info "Check status:"
        echo "  docker compose -f compose.testing.yml ps"
        echo ""
        print_info "Scan from host (recommended):"
        echo "  cd .. && python -m pyth --target http://localhost:8081 --safe --html"
        echo ""
        print_info "Scan from Docker container (use service names):"
        echo "  docker compose run --rm pyth --target http://php-vuln-app --safe --html"
        echo "  docker compose run --rm pyth --target 'http://dvwa/vulnerabilities/sqli/?id=&Submit=Submit' --safe --html"
        echo "  docker compose run --rm pyth --target 'http://dvwa/vulnerabilities/sqli_blind/?id=&Submit=Submit' --safe --html"
        echo "  docker compose run --rm pyth --target http://flask-vuln-app:5000 --safe --html"
        ;;

    3)
        print_warning "WARNING: The testing lab is INTENTIONALLY VULNERABLE!"
        print_warning "DO NOT expose it to the public internet!"
        echo ""
        read -p "Do you understand and want to continue? (yes/no): " confirm

        if [ "$confirm" != "yes" ]; then
            print_info "Deployment cancelled."
            exit 0
        fi

        print_info "Building Pythia Scanner and starting Testing Lab..."
        echo ""

        cd "$(dirname "$0")"
        mkdir -p ./data ./reports

        # Build Pythia image
        print_info "Building Pythia Scanner..."
        docker compose build

        # Start testing lab
        print_info "Starting Testing Lab..."
        docker compose -f compose.testing.yml up -d

        echo ""
        print_success "Both environments ready!"
        echo ""
        print_info "Testing Lab (accessible from host):"
        echo "  - DVWA: http://localhost:8080"
        echo "  - PHP App: http://localhost:8081"
        echo "  - Flask App: http://localhost:8082"
        echo ""
        print_info "Scan testing lab from host (recommended):"
        echo "  cd .. && python -m pyth --target http://localhost:8081 --safe --html"
        echo ""
        print_info "Scan from Docker container (use service names in sqli-lab network):"
        echo "  docker compose run --rm pyth --target http://php-vuln-app --safe --html"
        echo "  docker compose run --rm pyth --target 'http://dvwa/vulnerabilities/sqli/?id=&Submit=Submit' --safe --html"
        echo "  docker compose run --rm pyth --target 'http://dvwa/vulnerabilities/sqli_blind/?id=&Submit=Submit' --safe --html"
        echo "  docker compose run --rm pyth --target http://flask-vuln-app:5000 --safe --html"
        ;;

    4)
        print_info "Stopping all services..."
        echo ""

        cd "$(dirname "$0")"

        # Stop testing lab if running
        if docker compose -f compose.testing.yml ps -q 2>/dev/null | grep -q .; then
            print_info "Stopping testing lab..."
            docker compose -f compose.testing.yml down
        fi

        echo ""
        print_success "All services stopped"
        ;;

    5)
        print_warning "WARNING: This will remove ALL containers and data!"
        print_warning "Reports and database will be PERMANENTLY DELETED!"
        echo ""
        read -p "Are you sure? Type 'DELETE' to confirm: " confirm

        if [ "$confirm" != "DELETE" ]; then
            print_info "Reset cancelled."
            exit 0
        fi

        print_info "Removing all containers and data..."
        echo ""

        cd "$(dirname "$0")"

        # Remove testing lab
        if docker compose -f compose.testing.yml ps -q 2>/dev/null | grep -q . || \
           docker compose -f compose.testing.yml ps -a -q 2>/dev/null | grep -q .; then
            print_info "Removing testing lab..."
            docker compose -f compose.testing.yml down -v
        fi

        # Remove Pythia image
        print_info "Removing Pythia image..."
        docker compose down 2>/dev/null || true

        # Remove data directories
        if [ -d "./data" ]; then
            print_info "Removing ./data directory..."
            rm -rf ./data
        fi

        if [ -d "./reports" ]; then
            print_info "Removing ./reports directory..."
            rm -rf ./reports
        fi

        echo ""
        print_success "All containers and data removed"
        ;;

    *)
        print_error "Invalid choice. Please run the script again."
        exit 1
        ;;
esac

echo ""
echo "========================================"
echo ""
