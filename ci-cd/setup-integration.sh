#!/bin/bash

# NMAT CI/CD Integration Setup Script
# Helps configure NMAT for CI/CD pipelines

set -e

echo "========================================="
echo "NMAT CI/CD Integration Setup"
echo "========================================="
echo ""

# Function to detect CI/CD platform
detect_platform() {
    if [ -n "$GITHUB_ACTIONS" ]; then
        echo "github"
    elif [ -n "$GITLAB_CI" ]; then
        echo "gitlab"
    elif [ -n "$JENKINS_HOME" ]; then
        echo "jenkins"
    elif [ -n "$CIRCLECI" ]; then
        echo "circleci"
    elif [ -n "$TRAVIS" ]; then
        echo "travis"
    else
        echo "unknown"
    fi
}

# Function to install NMAT CLI
install_nmat_cli() {
    echo "Installing NMAT CLI..."

    if command -v npm &> /dev/null; then
        npm install -g nmat-cli
        echo "✓ NMAT CLI installed successfully"
    else
        echo "✗ Error: npm not found. Please install Node.js first."
        exit 1
    fi
}

# Function to configure NMAT
configure_nmat() {
    local api_url=$1
    local api_key=$2

    echo "Configuring NMAT..."
    nmat configure --url "$api_url" --key "$api_key"
    echo "✓ NMAT configured successfully"
}

# Function to run test scan
run_test_scan() {
    local target=$1

    echo "Running test scan on $target..."
    nmat ci-scan \
        --target "$target" \
        --output nmat-test-report.json \
        --timeout 300

    if [ -f nmat-test-report.json ]; then
        echo "✓ Test scan completed successfully"
        cat nmat-test-report.json | head -20
    else
        echo "✗ Test scan failed"
        exit 1
    fi
}

# Function to setup platform-specific configuration
setup_platform_config() {
    local platform=$1

    case $platform in
        github)
            echo "Setting up GitHub Actions..."
            mkdir -p .github/workflows
            cp ci-cd/github-actions.yml .github/workflows/nmat-scan.yml
            echo "✓ GitHub Actions workflow created at .github/workflows/nmat-scan.yml"
            echo ""
            echo "Next steps:"
            echo "1. Add NMAT_API_URL to GitHub Secrets"
            echo "2. Add NMAT_API_KEY to GitHub Secrets"
            echo "3. Add TARGET_URL to GitHub Secrets"
            echo "4. Commit and push the workflow file"
            ;;

        gitlab)
            echo "Setting up GitLab CI..."
            cp ci-cd/gitlab-ci.yml .gitlab-ci.yml
            echo "✓ GitLab CI configuration created at .gitlab-ci.yml"
            echo ""
            echo "Next steps:"
            echo "1. Add NMAT_API_KEY as GitLab CI/CD variable"
            echo "2. Update NMAT_API_URL in .gitlab-ci.yml"
            echo "3. Update TARGET_URL in .gitlab-ci.yml"
            echo "4. Commit and push the configuration"
            ;;

        jenkins)
            echo "Setting up Jenkins..."
            cp ci-cd/Jenkinsfile Jenkinsfile
            echo "✓ Jenkinsfile created"
            echo ""
            echo "Next steps:"
            echo "1. Add 'nmat-api-url' credential in Jenkins"
            echo "2. Add 'nmat-api-key' credential in Jenkins"
            echo "3. Create a Jenkins pipeline job"
            echo "4. Point the job to this repository"
            ;;

        *)
            echo "Platform not detected or unknown"
            echo "Available configurations:"
            echo "  - GitHub Actions: ci-cd/github-actions.yml"
            echo "  - GitLab CI: ci-cd/gitlab-ci.yml"
            echo "  - Jenkins: ci-cd/Jenkinsfile"
            ;;
    esac
}

# Function to create Docker image for CI/CD
create_docker_image() {
    cat > Dockerfile.nmat << 'EOF'
FROM node:18-alpine

# Install NMAT CLI
RUN npm install -g nmat-cli

# Create working directory
WORKDIR /app

# Copy entrypoint script
COPY ci-cd/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
EOF

    cat > ci-cd/docker-entrypoint.sh << 'EOF'
#!/bin/sh

# Configure NMAT if credentials are provided
if [ -n "$NMAT_API_URL" ] && [ -n "$NMAT_API_KEY" ]; then
    nmat configure --url "$NMAT_API_URL" --key "$NMAT_API_KEY"
fi

# Execute command
exec nmat "$@"
EOF

    echo "✓ Docker configuration created"
    echo ""
    echo "Build Docker image with:"
    echo "  docker build -f Dockerfile.nmat -t nmat-scanner ."
    echo ""
    echo "Run scan with:"
    echo "  docker run -e NMAT_API_URL=... -e NMAT_API_KEY=... nmat-scanner ci-scan --target https://example.com"
}

# Function to generate sample configuration
generate_sample_config() {
    cat > nmat-config.json << 'EOF'
{
  "apiUrl": "http://localhost:8080",
  "targets": [
    "https://example.com"
  ],
  "scanConfig": {
    "activeScanning": true,
    "passiveScanning": true,
    "maxDepth": 3,
    "maxRequests": 100
  },
  "scanPolicy": {
    "vulnerabilityChecks": {
      "sqlInjection": true,
      "xss": true,
      "csrf": true,
      "ssrf": true
    }
  },
  "reporting": {
    "formats": ["json", "html", "xml"],
    "outputDir": "./reports"
  },
  "notifications": {
    "slack": {
      "enabled": false,
      "webhookUrl": ""
    },
    "email": {
      "enabled": false,
      "recipients": []
    }
  },
  "failureThresholds": {
    "critical": 0,
    "high": 0,
    "medium": 10
  }
}
EOF

    echo "✓ Sample configuration created at nmat-config.json"
}

# Main script
main() {
    echo "Detected platform: $(detect_platform)"
    echo ""

    # Parse command line arguments
    ACTION=${1:-interactive}

    case $ACTION in
        install)
            install_nmat_cli
            ;;

        configure)
            configure_nmat "${2}" "${3}"
            ;;

        test)
            run_test_scan "${2:-https://httpbin.org}"
            ;;

        setup)
            setup_platform_config "$(detect_platform)"
            ;;

        docker)
            create_docker_image
            ;;

        sample)
            generate_sample_config
            ;;

        all)
            install_nmat_cli
            generate_sample_config
            setup_platform_config "$(detect_platform)"
            create_docker_image
            echo ""
            echo "========================================="
            echo "Setup complete!"
            echo "========================================="
            ;;

        interactive|*)
            echo "NMAT CI/CD Integration Setup"
            echo ""
            echo "What would you like to do?"
            echo "1) Install NMAT CLI"
            echo "2) Configure NMAT"
            echo "3) Run test scan"
            echo "4) Setup platform configuration"
            echo "5) Create Docker image"
            echo "6) Generate sample configuration"
            echo "7) All of the above"
            echo ""
            read -p "Enter choice [1-7]: " choice

            case $choice in
                1) install_nmat_cli ;;
                2)
                    read -p "API URL: " api_url
                    read -p "API Key: " api_key
                    configure_nmat "$api_url" "$api_key"
                    ;;
                3)
                    read -p "Target URL: " target
                    run_test_scan "$target"
                    ;;
                4) setup_platform_config "$(detect_platform)" ;;
                5) create_docker_image ;;
                6) generate_sample_config ;;
                7)
                    install_nmat_cli
                    generate_sample_config
                    setup_platform_config "$(detect_platform)"
                    create_docker_image
                    echo "Setup complete!"
                    ;;
                *) echo "Invalid choice" ;;
            esac
            ;;
    esac
}

# Run main function
main "$@"
