package updater

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

var (
	GeoUpdateHook func(geoType string, updating bool, skipped bool, updateErr error)
)

func sendGeoUpdateStatus(geoType string, updating bool, skipped bool, updateErr error) {
	if GeoUpdateHook != nil {
		GeoUpdateHook(geoType, updating, skipped, updateErr)
	}
}

var (
	geoUpdaterMu       sync.Mutex
	geoUpdateCancel    context.CancelFunc
	geoUpdaterInterval int
)

func geoUpdateOverdue(lastUpdate time.Time, intervalHours int, now time.Time) bool {
	if intervalHours <= 0 || lastUpdate.IsZero() {
		return false
	}
	return lastUpdate.Add(time.Duration(intervalHours) * time.Hour).Before(now)
}

func StopGeoUpdater() {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()
	stopGeoUpdaterLocked()
}

func stopGeoUpdaterLocked() {
	if geoUpdateCancel != nil {
		geoUpdateCancel()
		geoUpdateCancel = nil
	}
	geoUpdaterInterval = 0
}

func RegisterGeoUpdaterWithCancel() {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()

	if updateInterval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %d", updateInterval)
		stopGeoUpdaterLocked()
		return
	}

	// 热更新配置会反复走到这里。间隔没变就复用已有 ticker，避免每次都补更一遍。
	if geoUpdateCancel != nil && geoUpdaterInterval == updateInterval {
		return
	}

	stopGeoUpdaterLocked()

	ctx, cancel := context.WithCancel(context.Background())
	geoUpdateCancel = cancel
	geoUpdaterInterval = updateInterval
	interval := updateInterval

	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Hour)
		defer ticker.Stop()

		lastUpdate, err := getUpdateTime()
		if err != nil {
			log.Errorln("[GEO] Get GEO database update time error: %s", err.Error())
		} else {
			log.Infoln("[GEO] last update time %s", lastUpdate)
			if geoUpdateOverdue(lastUpdate, interval, time.Now()) {
				log.Infoln("[GEO] Database has not been updated for %v, update now", time.Duration(interval)*time.Hour)
				if err := UpdateGeoDatabases(); err != nil {
					log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				}
			}
		}

		for {
			select {
			case <-ctx.Done():
				log.Infoln("[GEO] Geo updater stopped")
				return
			case <-ticker.C:
				log.Infoln("[GEO] updating database every %d hours", interval)
				if err := UpdateGeoDatabases(); err != nil {
					log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				}
			}
		}
	}()
}
