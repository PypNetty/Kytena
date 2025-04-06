# Kytena Architecture Documentation

## Table of Contents
1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [System Components](#system-components)
4. [Data Flow](#data-flow)
5. [Key Workflows](#key-workflows)
6. [Integration Points](#integration-points)
7. [Future Extensions](#future-extensions)

## Overview

Kytena is an intelligent security orchestrator for Kubernetes that manages the lifecycle of known security risks with traceability and automatic reevaluation. Its primary purpose is to provide a framework for documenting, tracking, and managing accepted security exceptions in Kubernetes environments.

The architecture is designed around a central concept: the **KnownRisk**. This represents a security vulnerability or risk that has been identified, evaluated, and explicitly accepted for a limited period of time.

The system follows a modular design with several key components:
- Core data structures for representing risks and workloads
- Persistent storage for KnownRisks
- Automated reevaluation system
- Vulnerability scanner integration
- Command-line interface for interaction

## Core Concepts

### KnownRisk
A KnownRisk is the fundamental entity in Kytena, representing an acknowledged security vulnerability that is temporarily accepted. Each KnownRisk includes:

- Unique identifier
- Reference to the affected vulnerability (e.g., CVE number)
- Information about the affected workload
- Justification for accepting the risk
- Who accepted the risk and when
- Expiration date
- Severity level
- Current status (Active, Expired, Resolved)

### Workload
A Workload represents a Kubernetes resource that might be affected by security vulnerabilities. It includes:

- Resource name and namespace
- Resource type (Deployment, StatefulSet, etc.)
- Business criticality rating
- Associated image ID
- Labels and annotations

### Vulnerability Findings
Vulnerability Findings represent security issues detected by scanners. They include:

- Vulnerability identifier and title
- Description and severity
- Affected component and version
- Fixed version information
- References and metadata

## System Components

The system is composed of the following key components:

### Core Domain Model
- `knownrisk`: Package containing the KnownRisk entity definition, validation logic, and lifecycle management.
- `workload`: Package containing the Workload entity definition and related utilities.

### Persistence Layer
- `repository`: Interface for KnownRisk persistence operations
- `FileRepository`: Implementation that stores KnownRisks as YAML files

### Reevaluation System
- `reevaluator`: Component that periodically checks KnownRisks for expiration and status changes
- `notification`: System for generating alerts when risks expire or approach expiration

### Scanner Integration
- `scanner`: Interfaces and utilities for integrating with vulnerability scanners
- `Trivy` and `Falco` scanner implementations (simulated)
- `orchestrator`: Component that coordinates scans and processes results

### Command Line Interface
- `cli`: Cobra-based CLI structure with various commands for interacting with the system

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLI Layer                              │
│  ┌─────────┐  ┌────────┐  ┌──────────┐  ┌────────┐  ┌────────┐  │
│  │ create  │  │  get   │  │   list   │  │ update │  │ delete │  │
│  └─────────┘  └────────┘  └──────────┘  └────────┘  └────────┘  │
│  ┌─────────┐  ┌────────────────────┐    ┌──────────────────┐    │
│  │ monitor │  │      scan          │    │    dashboard     │    │
│  └─────────┘  └────────────────────┘    └──────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                          │                   ▲
                          ▼                   │
┌─────────────────────────────────────────────────────────────────┐
│                       Core Domain Layer                         │
│  ┌─────────────────────────┐      ┌─────────────────────────┐   │
│  │      KnownRisk          │◄────►│        Workload         │   │
│  └─────────────────────────┘      └─────────────────────────┘   │
│                  │                                               │
│                  ▼                                               │
│  ┌─────────────────────────┐      ┌─────────────────────────┐   │
│  │      Repository         │◄────►│      Reevaluator        │   │
│  └─────────────────────────┘      └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                          │                   ▲
                          ▼                   │
┌─────────────────────────────────────────────────────────────────┐
│                      Integration Layer                          │
│  ┌─────────────────────────┐      ┌─────────────────────────┐   │
│  │   Scanner Registry      │◄────►│   Scan Orchestrator     │   │
│  └─────────────────────────┘      └─────────────────────────┘   │
│                  │                                               │
│                  ▼                                               │
│  ┌─────────────────────────┐      ┌─────────────────────────┐   │
│  │    Trivy Scanner        │      │     Falco Scanner       │   │
│  └─────────────────────────┘      └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### KnownRisk Creation Flow
1. A vulnerability is identified (manually or through scanning)
2. A KnownRisk is created with relevant details
3. The KnownRisk is validated for completeness and correctness
4. The KnownRisk is stored in the repository
5. The KnownRisk becomes available for monitoring

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Scanner │────►  Create   │────►  Validate │────►   Store   │
└─────────┘     │ KnownRisk │     │          │     │          │
                └──────────┘     └──────────┘     └──────────┘
```

### Reevaluation Flow
1. The reevaluator periodically wakes up (e.g., every hour)
2. It fetches all active KnownRisks from the repository
3. For each KnownRisk, it checks if it's expired
4. If a KnownRisk is expired, its status is updated
5. Notifications are generated for expired risks
6. Updated KnownRisks are saved back to the repository

```
┌──────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Reevaluator │────►   Fetch   │────►   Check   │────►  Update   │
│    Timer     │     │ KnownRisks│     │  Status  │     │  Status  │
└──────────────┘     └──────────┘     └──────────┘     └──────────┘
                                          │
                                          ▼
                                     ┌──────────┐
                                     │ Generate │
                                     │ Alerts   │
                                     └──────────┘
```

### Scan Flow
1. A scan is triggered via the CLI
2. The scan orchestrator coordinates with registered scanners
3. Each scanner performs its scan operation
4. Results are collected and aggregated
5. Findings are processed and matched to workloads
6. Proposed KnownRisks are generated based on findings
7. Results are displayed to the user

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│   CLI    │────►    Scan   │────►  Scanner  │────►   Collect │
│ Command  │     │Orchestrate│     │  Plugins │     │  Results │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
                                                         │
                                                         ▼
┌──────────┐     ┌──────────┐     ┌───────────────────────┐
│  Display │◄────┤  Propose │◄────┤      Process          │
│  Results │     │ KnownRisks│     │  Vulnerability Data  │
└──────────┘     └──────────┘     └───────────────────────┘
```

## Key Workflows

### Managing a New Vulnerability
1. Detect: A vulnerability is detected in a Kubernetes workload
2. Assess: The vulnerability is assessed for impact and risk
3. Decide: A decision is made whether to fix immediately or accept temporarily
4. Document: If accepted, a KnownRisk is created with justification and expiry
5. Monitor: The KnownRisk is monitored for expiration
6. Resolve: Either the vulnerability is fixed or the KnownRisk is extended

### Security Posture Assessment
1. Run the dashboard command to get an overview of security status
2. Identify high-risk workloads and critical vulnerabilities
3. Prioritize remediation based on risk scores and business impact
4. Track progress by monitoring changes in risk scores over time

## Integration Points

Kytena is designed to integrate with several external systems:

### Vulnerability Scanners
- Integration with container image scanners (e.g., Trivy)
- Integration with runtime security tools (e.g., Falco)
- Future: Integration with compliance scanners

### Kubernetes
- Future: Direct querying of Kubernetes API for workload information
- Future: Kubernetes operator for continuous monitoring

### Notification Systems
- Current: File-based logging of notifications
- Current: Console output for interactive use
- Future: Email, Slack, or other messaging integrations

## Future Extensions

The architecture is designed to be extensible in several directions:

### Enhanced Scanner Integration
- Replace simulated scanners with real integrations
- Add support for more scanner types
- Implement real-time vulnerability feed processing

### Advanced Risk Analysis
- Machine learning for risk prioritization
- Historical trend analysis
- Predictive security posture modeling

### Expanded UI Options
- Web-based dashboard
- Integration with visualization tools
- Advanced reporting capabilities

### Enterprise Features
- Multi-cluster support
- Role-based access control
- Integration with enterprise authentication systems
- Compliance reporting