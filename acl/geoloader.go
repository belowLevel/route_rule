package acl

import (
	"fmt"
	"github.com/belowLevel/route_rule/acl/v2geo"
	"github.com/oschwald/maxminddb-golang/v2"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	geositeFilename = "geosite.dat"
	geositeURL      = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
	geoDlTmpPattern = ".hysteria-geoloader.dlpart.*"

	mmdbFilename = "country.mmdb"
	mmdbURL      = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"

	geoDefaultUpdateInterval = 7 * 24 * time.Hour // 7 days
)

var _ GeoLoader = (*GeoLoaderT)(nil)

// GeoLoader provides the on-demand GeoIP/GeoSite database
// loading functionality required by the ACL engine.
// Empty filenames = automatic download from built-in URLs.
type GeoLoaderT struct {
	GeoIPFilename   string        `json:"-" yaml:"-"`
	GeoSiteFilename string        `json:"-" yaml:"-"`
	UpdateInterval  time.Duration `json:"-" yaml:"-"`
	GeositeURL      string        `json:"geosite-url" yaml:"geosite-url"`

	DownloadFunc    func(filename, url string) `json:"-" yaml:"-"`
	DownloadErrFunc func(err error)            `json:"-" yaml:"-"`

	geoipMap   map[string]*v2geo.GeoIP   `json:"-" yaml:"-"`
	geositeMap map[string]*v2geo.GeoSite `json:"-" yaml:"-"`

	geositeSSKVMap map[string]*v2geo.Set `json:"-" yaml:"-"`
	MmdbURL        string                `json:"mmdb-url" yaml:"mmdb-url"`

	MMDBFilename string     `json:"-" yaml:"-"`
	ipreader     *IPReader  `json:"-" yaml:"-"`
	AutoDL       bool       `json:"auto-download" yaml:"auto-download"`
	lock         sync.Mutex `json:"-" yaml:"-"`
}

func (l *GeoLoaderT) shouldDownload(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return true
	}
	if info.Size() == 0 {
		// empty files are loadable by v2geo, but we consider it broken
		return true
	}
	dt := time.Now().Sub(info.ModTime())
	if l.UpdateInterval == 0 {
		return dt > geoDefaultUpdateInterval
	} else {
		return dt > l.UpdateInterval
	}
}

func (l *GeoLoaderT) downloadAndCheck(filename, url string, checkFunc func(filename string) error) error {
	l.DownloadFunc(filename, url)

	resp, err := http.Get(url)
	if err != nil {
		l.DownloadErrFunc(err)
		return err
	}
	defer resp.Body.Close()

	f, err := os.CreateTemp(".", geoDlTmpPattern)
	if err != nil {
		l.DownloadErrFunc(err)
		return err
	}
	defer os.Remove(f.Name())

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		f.Close()
		l.DownloadErrFunc(err)
		return err
	}
	f.Close()

	err = checkFunc(f.Name())
	if err != nil {
		l.DownloadErrFunc(fmt.Errorf("integrity check failed: %w", err))
		return err
	}

	err = os.Rename(f.Name(), filename)
	if err != nil {
		l.DownloadErrFunc(fmt.Errorf("rename failed: %w", err))
		return err
	}

	return nil
}

func (l *GeoLoaderT) LoadGeoSiteSSKV() (map[string]*v2geo.Set, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.geositeSSKVMap != nil {
		return l.geositeSSKVMap, nil
	}
	filename := l.GeoSiteFilename
	if filename == "" {
		filename = geositeFilename
	}
	downUrl := l.GeositeURL
	if downUrl == "" {
		downUrl = geositeURL
	}
	if l.AutoDL {
		if !l.shouldDownload(filename) {
			m, err := v2geo.LoadGeoSiteSSKV(filename)
			if err == nil {
				l.geositeSSKVMap = m
				return m, nil
			}
			// file is broken, download it again
		}
		err := l.downloadAndCheck(filename, downUrl, func(filename string) error {
			_, err := v2geo.LoadGeoSite(filename)
			return err
		})
		if err != nil {
			// as long as the previous download exists, fallback to it
			if _, serr := os.Stat(filename); os.IsNotExist(serr) {
				return nil, err
			}
		}
	}
	m, err := v2geo.LoadGeoSiteSSKV(filename)
	if err != nil {
		return nil, err
	}
	l.geositeSSKVMap = m
	return m, nil
}

func (l *GeoLoaderT) LoadGeoMMDB() (*IPReader, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.ipreader != nil {
		return l.ipreader, nil
	}
	filename := l.MMDBFilename
	if filename == "" {
		filename = mmdbFilename
	}
	downUrl := l.MmdbURL
	if downUrl == "" {
		downUrl = mmdbURL
	}
	if l.AutoDL {
		if !l.shouldDownload(filename) {
			m, err := NewIPInstance(filename)
			if err == nil {
				l.ipreader = m
				return m, nil
			}
			// file is broken, download it again
		}
		err := l.downloadAndCheck(filename, downUrl, func(filename string) error {
			return nil
		})
		if err != nil {
			// as long as the previous download exists, fallback to it
			if _, serr := os.Stat(filename); os.IsNotExist(serr) {
				return nil, err
			}
		}
	}
	m, err := NewIPInstance(filename)
	if err != nil {
		return nil, err
	}
	l.ipreader = m
	return m, nil
}

func NewIPInstance(mmdbPath string) (*IPReader, error) {
	mmdb, err := maxminddb.Open(mmdbPath)
	if err != nil {
		return nil, err
	}
	return &IPReader{Reader: mmdb}, nil
}

func (l *GeoLoaderT) CloseMMdb() {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.ipreader != nil {
		l.ipreader.lock.Lock()
		defer l.ipreader.lock.Unlock()
		l.ipreader.close = true
		l.ipreader.Close()
	}
}
