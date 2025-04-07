# Nom du binaire
BINARY_NAME=kytena

# Variables personnalisables
MIN_SEVERITY?=Low
NAMESPACE?=
WORKLOAD?=
MAX_RESULTS?=100
TIMEOUT?=300
ACCEPT_PROPOSED?=false
IGNORE_EXISTING?=false

# 🆘 Aide - affiche les commandes disponibles
.PHONY: help
help: ## Affiche cette aide
	@echo ""
	@echo "📦 Kytena - Makefile Commands"
	@echo "---------------------------------------------"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "🔹 %-22s %s\n", $$1, $$2}'
	@echo ""

# 🧼 Nettoyage
clean: ## Supprime les binaires compilés
	@echo "🧼 Suppression des binaires..."
	@rm -f $(BINARY_NAME)

# 🔨 Compilation
build: ## Compile le binaire Kytena
	@echo "🔨 Compilation de Kytena..."
	go build -o $(BINARY_NAME) ./cmd

# 🧪 Tests unitaires
test: ## Lance tous les tests unitaires
	@echo "🧪 Tests en cours..."
	go test ./... -v

# 🧪 Test d’intégration Trivy
scan-trivy-test: ## Lance le test d’intégration avec Trivy
	@echo "🔎 Test d'intégration Trivy..."
	go test ./internal/scanner -run TestTrivyIntegration -v

# 🔍 Scan complet CLI
scan: ## Lance un scan complet avec Kytena CLI
	@echo "🔍 Scan avec Kytena CLI..."
	./$(BINARY_NAME) scan \
		--min-severity $(MIN_SEVERITY) \
		--namespace $(NAMESPACE) \
		--workload $(WORKLOAD) \
		--max-results $(MAX_RESULTS) \
		--timeout $(TIMEOUT) \
		$(if $(filter true,$(ACCEPT_PROPOSED)),--accept-proposed,) \
		$(if $(filter true,$(IGNORE_EXISTING)),--ignore-existing,)

# 📥 Installation de Trivy
install-trivy: ## Installe Trivy sur votre machine
	@echo "📥 Installation de Trivy..."
	@bash scripts/install-trivy.sh

# 🚀 Bootstrap complet
bootstrap: install-trivy build ## Installe Trivy et build Kytena
	@echo "🚀 Bootstrap terminé, prêt à scanner !"
