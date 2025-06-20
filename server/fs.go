package main

import (
	"database/sql"

	"github.com/9072997/tlspage/server/mountfs"
	"github.com/9072997/tlspage/server/sqlitefs"
	"github.com/spf13/afero"
)

func Fs(db *sql.DB, confDir string) (afero.Fs, error) {
	confFs, err := sqlitefs.New(db, "fs")
	if err != nil {
		return nil, err
	}
	err = confFs.MkdirAll("/www", 0755)
	if err != nil {
		return nil, err
	}
	err = confFs.MkdirAll("/local", 0755)
	if err != nil {
		return nil, err
	}

	wwwFs, err := sqlitefs.New(db, "www")
	if err != nil {
		return nil, err
	}

	osFs := afero.NewBasePathFs(afero.NewOsFs(), confDir)

	mount := mountfs.New()
	mount.Mount("/", confFs)
	mount.Mount("/www", wwwFs)
	mount.Mount("/local", osFs)

	return mount, nil
}
