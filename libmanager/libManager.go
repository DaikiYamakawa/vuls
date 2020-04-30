package libmanager

import (
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// FillLibrary fills LibraryScanner informations
func FillLibrary(r *models.ScanResult) (totalCnt int, err error) {
	// initialize trivy's logger and db
	err = log.InitLogger(false, false)
	if err != nil {
		return 0, err
	}

	// TODO Define a path of cachedir in config.toml
	cacheDir := utils.DefaultCacheDir()
	if err := db.Init(cacheDir); err != nil {
		return 0, err
	}

	util.Log.Info("Updating library db...")
	// TODO
	// https: //github.com/aquasecurity/trivy/blob/ad0bb7ce231ec6239e5f0b0a2ab09e5b1a3687e9/internal/standalone/run.go#L59
	// https://github.com/aquasecurity/trivy/blob/ad0bb7ce231ec6239e5f0b0a2ab09e5b1a3687e9/internal/operation/operation.go#L58
	// err := scanner.UpdateDB()
	// if err != nil {
	// 	return nil, xerrors.Errorf("failed to update %s advisories: %w", scanner.Type(), err)
	// }

	for _, lib := range r.LibraryScanners {
		vinfos, err := lib.Scan()
		if err != nil {
			return 0, err
		}
		for _, vinfo := range vinfos {
			r.ScannedCves[vinfo.CveID] = vinfo
		}
		totalCnt += len(vinfos)
	}
	db.Close()

	return totalCnt, nil
}
