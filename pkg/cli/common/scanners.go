package common

import (
	"fmt"
	"strings"

	"github.com/PypNetty/Kytena/pkg/scanner"
)

// ScannerConfig contient la configuration commune pour les scanners
type ScannerConfig struct {
	UseRealK8s      bool
	KubeConfig      string
	MinimumSeverity string
	TimeoutSeconds  int
}

// TrivyConfig contient la configuration spécifique pour Trivy
type TrivyConfig struct {
	BinaryPath string
	CachePath  string
	NoCache    bool
	UpdateDB   bool
	SkipFS     bool
	CustomArgs []string
	ScannerConfig
}

// ScannerFactory gère la création et la configuration des scanners
type ScannerFactory struct {
	logger Logger
}

// NewScannerFactory crée une nouvelle factory de scanners
func NewScannerFactory(logger Logger) *ScannerFactory {
	return &ScannerFactory{
		logger: logger,
	}
}

// CreateRegistry crée et configure un nouveau registry de scanners
func (f *ScannerFactory) CreateRegistry(trivyConfig TrivyConfig) (*scanner.VulnerabilityScannerRegistry, error) {
	registry := scanner.NewVulnerabilityScannerRegistry()

	// Créer et configurer le scanner Trivy
	trivyScanner, err := f.createTrivyScanner(trivyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Trivy scanner: %w", err)
	}
	registry.RegisterScanner(trivyScanner)

	// Ajouter d'autres scanners ici au besoin
	// registry.RegisterScanner(otherScanner)

	return registry, nil
}

// createTrivyScanner crée et configure un scanner Trivy
func (f *ScannerFactory) createTrivyScanner(config TrivyConfig) (scanner.VulnerabilityScanner, error) {
	f.logger.Debug("Creating Trivy scanner with config: %+v", config)

	scannerConfig := map[string]interface{}{
		"binaryPath":      config.BinaryPath,
		"cachePath":       config.CachePath,
		"noCache":         config.NoCache,
		"updateDB":        config.UpdateDB,
		"skipFS":          config.SkipFS,
		"useRealK8s":      config.UseRealK8s,
		"kubeconfig":      config.KubeConfig,
		"minimumSeverity": strings.ToUpper(config.MinimumSeverity),
		"timeoutSeconds":  config.TimeoutSeconds,
	}

	if len(config.CustomArgs) > 0 {
		scannerConfig["extraArgs"] = config.CustomArgs
	}

	trivyScanner := scanner.NewTrivyScanner(f.logger)
	if err := trivyScanner.Configure(scannerConfig); err != nil {
		return nil, fmt.Errorf("failed to configure Trivy scanner: %w", err)
	}

	return trivyScanner, nil
}

// ValidateScannerConfig valide la configuration d'un scanner
func (f *ScannerFactory) ValidateScannerConfig(config ScannerConfig) error {
	if config.TimeoutSeconds <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	severity := strings.ToUpper(config.MinimumSeverity)
	validSeverities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	valid := false
	for _, s := range validSeverities {
		if severity == s {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid severity: %s. Must be one of: %s",
			config.MinimumSeverity, strings.Join(validSeverities, ", "))
	}

	return nil
}
