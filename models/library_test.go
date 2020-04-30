package models

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func TestScan(t *testing.T) {
	var tests = []struct {
		path string
		pkgs []types.Library
	}{
		{
			path: "app/package-lock.json",
			pkgs: []types.Library{
				{
					Name:    "jquery",
					Version: "2.2.4",
				},
				{
					Name:    "@babel/traverse",
					Version: "7.4.4",
				},
			},
		},
	}

	if err := log.InitLogger(false, false); err != nil {
		t.Errorf("trivy logger failed")
	}

	cacheDir := utils.DefaultCacheDir()
	if err := db.Init(cacheDir); err != nil {
		t.Errorf("trivy db.Init failed")
	}
	for _, v := range tests {
		lib := LibraryScanner{
			Path: v.path,
			Libs: v.pkgs,
		}
		actual, err := lib.Scan()
		if err != nil {
			t.Errorf("error occurred")
		}
		if len(actual) == 0 {
			t.Errorf("no vuln found : actual: %v\n", actual)
		}
	}
	db.Close()
}
