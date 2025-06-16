package sqlitefs

import (
	"database/sql"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/afero"
)

type Fs struct {
	db    *sql.DB
	table string
}

// New creates a new SQLite-based filesystem
func New(db *sql.DB, table string) (*Fs, error) {
	// table must match the regex ^[a-zA-Z_][a-zA-Z0-9_]*$
	if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(table) {
		return nil, fmt.Errorf("invalid table name: %s", table)
	}

	fs := &Fs{db: db, table: table}
	if err := fs.initSchema(); err != nil {
		return nil, err
	}

	return fs, nil
}

// Initialize database schema
func (fs *Fs) initSchema() error {
	schema := `
		CREATE TABLE IF NOT EXISTS ` + fs.table + ` (
			path TEXT PRIMARY KEY,
			data BLOB,
			mode INTEGER,
			uid INTEGER,
			gid INTEGER,
			size INTEGER,
			is_dir BOOLEAN,
			atime INTEGER,
			mtime INTEGER,
			ctime INTEGER
		);
		-- create root directory
		INSERT OR IGNORE INTO ` + fs.table + ` (
			path, mode, size, is_dir, atime, mtime, ctime
		) VALUES (
		 	'/', 0755, 0, true, ?, ?, ?
		);
	`
	now := time.Now().Unix()
	_, err := fs.db.Exec(schema, now, now, now)
	return err
}

func clean(p string) string {
	p = strings.ReplaceAll(p, "\\", "/") // Normalize path separators
	p = path.Clean(p)                    // Clean up path
	if !path.IsAbs(p) {
		p = "/" + p // Ensure absolute path
	}
	p = path.Clean(p) // Clean again to remove any redundant slashes
	return p
}

// Create creates a file in the filesystem
func (fs *Fs) Create(name string) (afero.File, error) {
	name = clean(name)

	// Check if parent directory exists
	dir := path.Dir(name)
	if dir != "." && dir != "/" {
		if _, err := fs.Stat(dir); err != nil {
			return nil, fmt.Errorf("parent directory does not exist: %s", dir)
		}
	}

	now := time.Now().Unix()
	_, err := fs.db.Exec(`
		INSERT OR REPLACE INTO `+fs.table+` (
			path, data, mode, size, is_dir, atime, mtime, ctime
		)
		VALUES (?, ?, ?, 0, false, ?, ?, ?)`,
		name, []byte{}, 0644, now, now, now)

	if err != nil {
		return nil, err
	}

	return &File{
		fs:   fs,
		name: name,
		data: []byte{},
		mode: os.O_RDWR | os.O_CREATE | os.O_TRUNC,
	}, nil
}

// Mkdir creates a directory
func (fs *Fs) Mkdir(name string, perm os.FileMode) error {
	name = clean(name)

	// Check if already exists
	if _, err := fs.Stat(name); err == nil {
		return fmt.Errorf("directory already exists: %s", name)
	}

	now := time.Now().Unix()
	_, err := fs.db.Exec(`
		INSERT INTO `+fs.table+` (
			path, mode, size, is_dir, atime, mtime, ctime
		)
		VALUES (?, ?, 0, true, ?, ?, ?)`,
		name, int(perm), now, now, now)

	return err
}

// MkdirAll creates directory path and parents
func (fs *Fs) MkdirAll(p string, perm os.FileMode) error {
	p = clean(p)

	// Split path into components
	parts := strings.Split(p, "/")
	currentPath := ""

	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}

		if currentPath == "" {
			currentPath = part
		} else {
			currentPath = path.Join(currentPath, part)
		}

		// Check if this part exists
		if _, err := fs.Stat(currentPath); err != nil {
			// Create this directory
			if err := fs.Mkdir(currentPath, perm); err != nil {
				return err
			}
		}
	}

	return nil
}

// Open opens a file for reading
func (fs *Fs) Open(name string) (afero.File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

// OpenFile opens a file with specified flags and mode
func (fs *Fs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	name = clean(name)

	var data []byte
	var isDir bool

	row := fs.db.QueryRow("SELECT data, is_dir FROM "+fs.table+" WHERE path = ?", name)
	err := row.Scan(&data, &isDir)

	if err == sql.ErrNoRows {
		if flag&os.O_CREATE != 0 {
			return fs.Create(name)
		}
		return nil, os.ErrNotExist
	} else if err != nil {
		return nil, err
	}

	// Update access time
	fs.db.Exec("UPDATE "+fs.table+" SET atime = ? WHERE path = ?", time.Now().Unix(), name)

	return &File{
		fs:    fs,
		name:  name,
		data:  data,
		mode:  flag,
		isDir: isDir,
	}, nil
}

// Remove removes a file
func (fs *Fs) Remove(name string) error {
	name = clean(name)

	// Check if file exists and is not a directory with children
	var isDir bool
	row := fs.db.QueryRow("SELECT is_dir FROM "+fs.table+" WHERE path = ?", name)
	err := row.Scan(&isDir)

	if err == sql.ErrNoRows {
		return os.ErrNotExist
	} else if err != nil {
		return err
	}

	if isDir {
		// Check if directory has children
		var count int
		row = fs.db.QueryRow("SELECT COUNT(*) FROM "+fs.table+" WHERE path LIKE ? AND path != ?", name+"/%", name)
		row.Scan(&count)
		if count > 0 {
			return fmt.Errorf("directory not empty: %s", name)
		}
	}

	_, err = fs.db.Exec("DELETE FROM "+fs.table+" WHERE path = ?", name)
	return err
}

// RemoveAll removes directory and all children
func (fs *Fs) RemoveAll(path string) error {
	path = clean(path)
	_, err := fs.db.Exec("DELETE FROM "+fs.table+" WHERE path = ? OR path LIKE ?", path, path+"/%")
	return err
}

// Rename renames a file
func (fs *Fs) Rename(oldname, newname string) error {
	oldname = clean(oldname)
	newname = clean(newname)

	// Check if old file exists
	if _, err := fs.Stat(oldname); err != nil {
		return err
	}

	// Update the path
	_, err := fs.db.Exec("UPDATE "+fs.table+" SET path = ? WHERE path = ?", newname, oldname)
	return err
}

// Stat returns file info
func (fs *Fs) Stat(name string) (os.FileInfo, error) {
	name = clean(name)

	var mode int
	var size int64
	var isDir bool
	var mtime int64

	row := fs.db.QueryRow(`
		SELECT mode, size, is_dir, mtime
		FROM `+fs.table+` WHERE path = ?
	`, name)

	err := row.Scan(&mode, &size, &isDir, &mtime)
	if err == sql.ErrNoRows {
		return nil, os.ErrNotExist
	} else if err != nil {
		return nil, err
	}

	return &FileInfo{
		name:  filepath.Base(name),
		size:  size,
		mode:  os.FileMode(mode),
		mtime: time.Unix(mtime, 0),
		isDir: isDir,
	}, nil
}

// Name returns filesystem name
func (fs *Fs) Name() string {
	return "SqliteFs"
}

// Chmod changes file mode
func (fs *Fs) Chmod(name string, mode os.FileMode) error {
	name = clean(name)
	_, err := fs.db.Exec("UPDATE "+fs.table+" SET mode = ? WHERE path = ?", int(mode), name)
	return err
}

// Chown changes file ownership
func (fs *Fs) Chown(name string, uid, gid int) error {
	name = clean(name)
	_, err := fs.db.Exec("UPDATE "+fs.table+" SET uid = ?, gid = ? WHERE path = ?", uid, gid, name)
	return err
}

// Chtimes changes access and modification times
func (fs *Fs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	name = clean(name)
	_, err := fs.db.Exec("UPDATE "+fs.table+" SET atime = ?, mtime = ? WHERE path = ?",
		atime.Unix(), mtime.Unix(), name)
	return err
}
