# Kytena Usage Guide

## Table of Contents
1. [Installation](#installation)
2. [Basic Commands](#basic-commands)
3. [Creating and Managing KnownRisks](#creating-and-managing-knownrisks)
4. [Scanning for Vulnerabilities](#scanning-for-vulnerabilities)
5. [Monitoring](#monitoring)
6. [Dashboard and Reporting](#dashboard-and-reporting)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites
- Go 1.19 or higher
- Git

### Building from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/PypNetty/Kytena.git
   cd Kytena
   ```

2. Build the binary:
   ```bash
   go build -o kyra cmd/kyra/main.go
   ```

3. Optionally, move the binary to your PATH:
   ```bash
   sudo mv kyra /usr/local/bin/
   ```

### Directory Structure
Kytena uses the following directories:
- `data/knownrisks/`: Storage location for KnownRisk YAML files
- `logs/`: Location for logs and notification records

## Basic Commands

Kytena offers a command-line interface with various commands:

### Getting Help
```bash
# Display general help
kyra --help

# Get help for a specific command
kyra command --help
```

### Configuration
```bash
# Specify a custom data directory
kyra --data-dir=/path/to/data

# Enable verbose output
kyra -v
```

## Creating and Managing KnownRisks

### Creating a KnownRisk
```bash
# Create a KnownRisk interactively
kyra create
```

The interactive creation process will prompt you for:
- Vulnerability ID (e.g., CVE number)
- Workload information (name, namespace, type)
- Justification for accepting the risk
- Who is accepting the risk
- Expiry timeframe
- Severity level

### Listing KnownRisks
```bash
# List all KnownRisks
kyra list

# Filter by status
kyra list --status=Active

# Filter by severity
kyra list --severity=High

# Filter by namespace
kyra list --namespace=production
```

### Viewing a KnownRisk
```bash
# Get details for a specific KnownRisk by ID
kyra get abc123

# Output in JSON format
kyra get abc123 --output=json
```

### Updating a KnownRisk
```bash
# Update interactively
kyra update abc123

# Extend expiry by 14 days
kyra update abc123 --extend=14

# Add a tag
kyra update abc123 --add-tags=frontend,urgent

# Mark as resolved
kyra update abc123 --status=resolved
```

### Deleting a KnownRisk
```bash
# Delete a KnownRisk (with confirmation)
kyra delete abc123

# Force delete without confirmation
kyra delete abc123 --force
```

## Scanning for Vulnerabilities

Kytena can simulate vulnerability scanning to identify security issues:

```bash
# Run a basic scan
kyra scan

# Filter by minimum severity
kyra scan --min-severity=High

# Filter by namespace
kyra scan --namespace=production

# Limit number of results
kyra scan --max-results=50

# Accept proposed KnownRisks automatically
kyra scan --accept-proposed
```

Scan results include:
- Detected vulnerabilities grouped by severity
- Affected workloads and components
- Proposed KnownRisks with suggested expiry periods

## Monitoring

The monitor command starts a continuous monitoring process:

```bash
# Start monitoring
kyra monitor

# Set a custom check interval (in seconds)
kyra monitor --interval=300

# Set a custom warning threshold (in hours)
kyra monitor --warning-threshold=48

# Specify a log directory
kyra monitor --log-dir=/path/to/logs
```

The monitor:
- Periodically checks for KnownRisks that have expired
- Generates notifications for expiring and expired risks
- Updates the status of KnownRisks automatically

## Dashboard and Reporting

The dashboard provides a visual overview of your security posture:

```bash
# Display the security dashboard
kyra dashboard

# Show detailed risk information
kyra dashboard --detail

# Filter by namespace
kyra dashboard --namespace=production

# Show more workloads in the risk ranking
kyra dashboard --max-workloads=10
```

The dashboard includes:
- Summary of risks by status and severity
- Overall risk score
- Visualizations of severity and status distributions
- Expiration timeline
- Ranking of workloads by risk
- Detailed risk view (with --detail flag)

## Advanced Usage

### Filtering and Sorting
Most commands support various filtering options:

```bash
# Combine multiple filters
kyra list --status=Active --severity=High --namespace=production

# Sort results
kyra list --sort=expiry
```

### Output Formats
Many commands support different output formats:

```bash
# Output as JSON
kyra list --output=json

# Output as detailed text
kyra get abc123 --output=text
```

## Troubleshooting

### Common Issues

#### Command Not Found
If you get "command not found" when trying to run Kytena, ensure:
- The binary is built correctly
- The binary is in your PATH or you're using the correct path

#### No Data Found
If commands show no data:
- Check that you're using the correct data directory
- Verify that KnownRisks have been created
- Check file permissions on the data directory

#### Scan Not Working
If scan command doesn't show results:
- Check the scanner configurations
- Ensure the necessary permissions are in place
- Verify that the timeout is sufficient

### Getting Help
If you need more help, please:
- Review the documentation in the `/docs` directory
- Check existing issues on GitHub
- Open a new issue with detailed information about your problem