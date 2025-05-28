package main

import (
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

var (
	Origin             = "example.com"
	PackageNameVersion = "tls.page v1.0.0"
	DqliteTimeout      = 60 * time.Second
	ShutdownTimeout    = 5 * time.Second
	ACMEDirectoryURL   = "https://acme-v02.api.letsencrypt.org/directory"
	ACMETimeout        = 60 * time.Second
	ACMERetries        = 3
	ACMERetryDelay     = 15 * time.Second
	CAAIdentifier      = "letsencrypt.org"
)

type Config struct {
	Origin             string        `toml:"origin"`
	PackageNameVersion string        `toml:"package_name_version"`
	DqliteTimeout      time.Duration `toml:"dqlite_timeout"`
	ShutdownTimeout    time.Duration `toml:"shutdown_timeout"`
	ACMEDirectoryURL   string        `toml:"acme_directory_url"`
	ACMETimeout        time.Duration `toml:"acme_timeout"`
	ACMERetries        int           `toml:"acme_retries"`
	ACMERetryDelay     time.Duration `toml:"acme_retry_delay"`
	CAAIdentifier      string        `toml:"caa_identifier"`
}

func LoadOrInitConfig(path string) error {
	// Check if file exists
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		// Write default config
		defaultCfg := Config{
			Origin:             Origin,
			PackageNameVersion: PackageNameVersion,
			DqliteTimeout:      DqliteTimeout,
			ShutdownTimeout:    ShutdownTimeout,
			ACMEDirectoryURL:   ACMEDirectoryURL,
			ACMETimeout:        ACMETimeout,
			ACMERetries:        ACMERetries,
			ACMERetryDelay:     ACMERetryDelay,
			CAAIdentifier:      CAAIdentifier,
		}
		data, err := toml.Marshal(&defaultCfg)
		if err != nil {
			return err
		}
		err = os.WriteFile(path, data, 0644)
		if err != nil {
			return err
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var cfg Config
	dec := toml.NewDecoder(f)
	_, err = dec.Decode(&cfg)
	if err != nil {
		return err
	}

	Origin = cfg.Origin
	PackageNameVersion = cfg.PackageNameVersion
	DqliteTimeout = cfg.DqliteTimeout
	ShutdownTimeout = cfg.ShutdownTimeout
	ACMEDirectoryURL = cfg.ACMEDirectoryURL
	ACMETimeout = cfg.ACMETimeout
	ACMERetries = cfg.ACMERetries
	ACMERetryDelay = cfg.ACMERetryDelay
	CAAIdentifier = cfg.CAAIdentifier

	return nil
}
