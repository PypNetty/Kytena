# Kyra - Orchestrateur Intelligent de Sécurité Kubernetes

![Status](https://img.shields.io/badge/Status-POC-yellow)
![Language](https://img.shields.io/badge/Language-Go-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Vision

Kyra est un orchestrateur de décisions de sécurité pour Kubernetes qui révolutionne la gestion des menaces dans les environnements cloud-native. Son innovation réside dans sa capacité unique à intégrer le contexte business aux décisions de sécurité, tout en maintenant une défense robuste contre les attaques sophistiquées.

## Le concept de KnownRisk

Le **KnownRisk** est la brique fondamentale de Kyra - une tolérance documentée à un écart de sécurité avec:
- Traçabilité (daté, signé, documenté)
- Contexte business et technique
- Durée de validité définie
- Mécanisme de réévaluation automatique
- Liens avec les workloads concernés

Lorsqu'une vulnérabilité est détectée mais ne peut être corrigée immédiatement (pour des raisons business, techniques, ou autres), Kyra permet de documenter cette décision comme un KnownRisk, puis de surveiller et réévaluer automatiquement ce risque au fil du temps.

## Fonctionnalités principales

- 🔍 **Observer** - Récupère des événements de sécurité de diverses sources
- 🔄 **Corréler** - Associe alertes, comportements, workloads et historique
- 🧠 **Contextualiser** - Prend en compte le business, le namespace, la criticité
- 📋 **Proposer** - Génère des PRs, tickets ou plans d'action adaptés
- 💾 **Mémoriser** - Archive les décisions humaines et leur justification
- ⚡ **Réagir** - Alerte si une vulnérabilité tolérée devient active
- 📝 **Expliquer** - Justifie chaque action, chaque lien logique ou refus

## État du projet

Kyra est actuellement en phase de Proof of Concept (POC). Les fonctionnalités sont en cours de développement et ne sont pas encore prêtes pour un environnement de production.

## Structure du projet

```
kyra/
├── cmd/              # Points d'entrée de l'application
│   └── kyra/         
│       └── main.go   # Point d'entrée principal
├── internal/         # Code privé de l'application
│   ├── knownrisk/    # Gestion des KnownRisks
│   │   ├── model.go
│   │   └── repository.go
│   └── workload/     # Gestion des Workloads
│       └── model.go
├── data/             # Données persistantes
│   └── knownrisks/   # Stockage des KnownRisks
├── go.mod            # Dépendances Go
└── README.md         # Ce fichier
```

## Installation

Instructions d'installation à venir lorsque le POC sera plus avancé.

## Utilisation

Instructions d'utilisation à venir lorsque le POC sera plus avancé.

## Développement

### Prérequis

- Go 1.19 ou supérieur
- Git

### Configuration de l'environnement de développement

1. Cloner le dépôt
   ```bash
   git clone https://github.com/PypNetty/Kyra.git
   cd Kyra
   ```

2. Installer les dépendances
   ```bash
   go mod tidy
   ```

3. Exécuter les tests
   ```bash
   go test ./...
   ```

### Gestion des branches

- `main` - Branche principale, toujours stable
- `feature/*` - Branches de fonctionnalités
- `bugfix/*` - Corrections de bugs
- `release/*` - Préparation des versions

## Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## Contact

Pour toute question ou suggestion concernant Kyra, n'hésitez pas à [ouvrir une issue](https://github.com/PypNetty/Kyra/issues).