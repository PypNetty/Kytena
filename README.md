# Kyra - Intelligent Kubernetes Security Orchestrator

![Status](https://img.shields.io/badge/Status-POC-yellow)
![Language](https://img.shields.io/badge/Language-Go-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Vision

Kyra is an intelligent security orchestrator for Kubernetes that revolutionizes vulnerability management in cloud-native environments. Its innovation lies in its unique ability to integrate business context into security decisions while maintaining robust defense against sophisticated attacks.

## The KnownRisk Concept

The **KnownRisk** is the fundamental building block of Kyra - a documented tolerance to a security deviation with:
- Traceability (dated, signed, documented)
- Business and technical context
- Defined validity period
- Automatic reevaluation mechanism
- Links to affected workloads

When a vulnerability is detected but cannot be fixed immediately (for business, technical, or other reasons), Kyra enables documenting this decision as a KnownRisk, then automatically monitoring and reevaluating this risk over time.

## Key Features

- 🔍 **Observe** - Collect security events from various sources
- 🔄 **Correlate** - Associate alerts, behaviors, workloads, and history
- 🧠 **Contextualize** - Consider business, namespace, and criticality
- 📋 **Propose** - Generate PRs, tickets, or adapted action plans
- 💾 **Memorize** - Archive human decisions and their justification
- ⚡ **React** - Alert if an accepted vulnerability becomes active
- 📝 **Explain** - Justify each action, each logical link, or refusal

## Project Status

Kyra is currently in a Proof of Concept (POC) phase. The core features have been implemented but are not yet ready for production environments.

### Implemented Features
- ✅ Core KnownRisk data model and lifecycle management
- ✅ YAML-based persistence 
- ✅ Periodic reevaluation system
- ✅ Notification system
- ✅ Simulated vulnerability scanner integration (Trivy, Falco)
- ✅ Comprehensive CLI with Cobra
- ✅ Security dashboard and reporting

### Planned Features
- 🔄 Real scanner integrations
- 🔄 Kubernetes API integration
- 🔄 Advanced alerting systems
- 🔄 Web-based UI

## Getting Started

### Prerequisites
- Go 1.19 or higher
- Git

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/PypNetty/Kyra.git
   cd Kyra
   ```

2. Build the binary:
   ```bash
   go build -o kyra cmd/kyra/main.go
   ```

3. Run Kyra:
   ```bash
   ./kyra --help
   ```

### Quick Start Guide

1. **Scan for vulnerabilities**:
   ```bash
   ./kyra scan --accept-proposed
   ```

2. **View your security dashboard**:
   ```bash
   ./kyra dashboard
   ```

3. **Monitor for expired risks**:
   ```bash
   ./kyra monitor
   ```

## Documentation

- Architecture details
- Comprehensive usage instructions
- Workflow examples

## Development

### Project Structure

```
kyra/
├── cmd/               # Command-line entry points
│   └── kyra/          
│       └── main.go    # Main entry point
├── internal/          # Private application code
│   ├── cli/           # CLI components
│   │   └── cmd/       # Cobra commands
│   ├── knownrisk/     # KnownRisk management
│   ├── scanner/       # Scanner integration
│   ├── reevaluator/   # Reevaluation system
│   └── workload/      # Workload management
├── data/              # Data storage
│   └── knownrisks/    # KnownRisk YAML files
├── logs/              # Log files
├── go.mod             # Go dependencies
└── README.md          # This file
```

### Key Commands

- **List KnownRisks**: `./kyra list`
- **Create KnownRisk**: `./kyra create`
- **View KnownRisk**: `./kyra get <id>`
- **Update KnownRisk**: `./kyra update <id>`
- **Run Security Scan**: `./kyra scan`
- **View Dashboard**: `./kyra dashboard`
- **Start Monitor**: `./kyra monitor`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.