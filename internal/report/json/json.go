// Package json renders report views as indented JSON files.
package json

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"pcapdigger/internal/report/model"
)

// WriteNetwork writes the network-engineering view as JSON.
func WriteNetwork(r *model.Report, outDir, baseName string) ([]string, error) {
	return writeOne(r.Network(), outDir, baseName+"-network-report.json")
}

// WriteSecurity writes the security-architect view as JSON.
func WriteSecurity(r *model.Report, outDir, baseName string) ([]string, error) {
	return writeOne(r.Security(), outDir, baseName+"-security-report.json")
}

// WriteExecutive writes the executive view as JSON.
func WriteExecutive(r *model.Report, outDir, baseName string) ([]string, error) {
	return writeOne(r.Executive(), outDir, baseName+"-executive-report.json")
}

func writeOne(v interface{}, outDir, fileName string) ([]string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}
	path := filepath.Join(outDir, fileName)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return []string{path}, nil
}
