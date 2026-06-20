// Package analyzer — Rule definitions and YAML loader.
//
// Rules are loaded from config/rules.yaml at startup and optionally
// reloaded on SIGHUP for zero-downtime rule updates.
//
// TODO(Phase 2): Implement full YAML parsing with gopkg.in/yaml.v3.

package analyzer

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Operator defines comparison operators for rule conditions.
type Operator string

const (
	OpGreaterThan    Operator = ">"
	OpGreaterOrEqual Operator = ">="
	OpLessThan       Operator = "<"
	OpLessOrEqual    Operator = "<="
	OpEqual          Operator = "=="
)

// Condition defines a threshold condition for a single metric.
type Condition struct {
	Operator Operator `yaml:"operator"`
	Value    float64  `yaml:"value"`
}

// Rule represents a single detection rule from rules.yaml.
type Rule struct {
	ID              string    `yaml:"id"`
	Description     string    `yaml:"description"`
	Metric          string    `yaml:"metric"`
	Condition       Condition `yaml:"condition"`
	Window          string    `yaml:"window"` // e.g., "30s", "5m"
	ConfidenceBase  float64   `yaml:"confidence_base"`
	MinSignals      int       `yaml:"min_signals"`
	SuggestedCause  string    `yaml:"suggested_cause"`
	SuggestedAction string    `yaml:"suggested_action"`
	Enabled         bool      `yaml:"enabled"`
}

// Correlation defines a multi-signal confidence boost.
type Correlation struct {
	Signals        []string `yaml:"signals"`
	Boost          float64  `yaml:"boost"`
	Interpretation string   `yaml:"interpretation"`
}

// RulesConfig is the top-level structure of rules.yaml.
type RulesConfig struct {
	Rules               []Rule        `yaml:"rules"`
	Correlations        []Correlation `yaml:"correlations"`
	SingleSignalPenalty float64       `yaml:"single_signal_penalty"`
	Thresholds          struct {
		Suppress   float64 `yaml:"suppress"`
		LogOnly    float64 `yaml:"log_only"`
		TakeAction float64 `yaml:"take_action"`
	} `yaml:"thresholds"`
}

// LoadRules parses config/rules.yaml and returns all enabled rules.
// TODO(Phase 2): Add file watcher for SIGHUP live reload.
func LoadRules(path string) ([]Rule, *RulesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading rules file %q: %w", path, err)
	}

	var cfg RulesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parsing rules YAML: %w", err)
	}

	// Filter to only enabled rules
	var enabled []Rule
	for _, r := range cfg.Rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}

	return enabled, &cfg, nil
}
