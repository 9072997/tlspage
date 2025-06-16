package sqlitefs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type File struct {
	fs       *Fs
	name     string
	data     []byte
	offset   int64
	mode     int
	isDir    bool
	modified bool
}

// File implementation methods

func (f *File) Close() error {
	if f.modified {
		// Save data back to database
		_, err := f.fs.db.Exec(`
			UPDATE `+f.fs.table+` SET data = ?, size = ?, mtime = ? WHERE path = ?`,
			f.data, len(f.data), time.Now().Unix(), f.name)
		return err
	}
	return nil
}

func (f *File) Read(p []byte) (n int, err error) {
	if f.offset >= int64(len(f.data)) {
		return 0, io.EOF
	}

	n = copy(p, f.data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *File) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}

	n = copy(p, f.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return n, err
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64

	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = f.offset + offset
	case io.SeekEnd:
		newOffset = int64(len(f.data)) + offset
	default:
		return 0, fmt.Errorf("invalid whence")
	}

	if newOffset < 0 {
		return 0, fmt.Errorf("negative position")
	}

	f.offset = newOffset
	return newOffset, nil
}

func (f *File) Write(p []byte) (n int, err error) {
	if f.mode&os.O_WRONLY == 0 && f.mode&os.O_RDWR == 0 {
		return 0, fmt.Errorf("file not open for writing")
	}

	// Extend data slice if necessary
	end := f.offset + int64(len(p))
	if end > int64(len(f.data)) {
		newData := make([]byte, end)
		copy(newData, f.data)
		f.data = newData
	}

	n = copy(f.data[f.offset:], p)
	f.offset += int64(n)
	f.modified = true
	return n, nil
}

func (f *File) WriteAt(p []byte, off int64) (n int, err error) {
	if f.mode&os.O_WRONLY == 0 && f.mode&os.O_RDWR == 0 {
		return 0, fmt.Errorf("file not open for writing")
	}

	// Extend data slice if necessary
	end := off + int64(len(p))
	if end > int64(len(f.data)) {
		newData := make([]byte, end)
		copy(newData, f.data)
		f.data = newData
	}

	n = copy(f.data[off:], p)
	f.modified = true
	return n, nil
}

func (f *File) Name() string {
	return f.name
}

// ReadDir reads the contents of the directory associated with the file f
// and returns a slice of DirEntry values in directory order. Subsequent
// calls on the same file will yield later DirEntry records in the directory.
//
// If n > 0, ReadDir returns at most n DirEntry records. In this case, if
// ReadDir returns an empty slice, it will return an error explaining why.
// At the end of a directory, the error is io.EOF.
//
// If n <= 0, ReadDir returns all the DirEntry records remaining in the
// directory. When it succeeds, it returns a nil error (not io.EOF).
func (f *File) Readdir(count int) ([]os.FileInfo, error) {
	if !f.isDir {
		return nil, fmt.Errorf("not a directory")
	}

	query := `
		SELECT path, mode, size, is_dir, mtime
		FROM ` + f.fs.table + `
		WHERE path LIKE ? AND path != ? AND path NOT LIKE ? 
		ORDER BY path
	`
	rows, err := f.fs.db.Query(query, f.name+"/%", f.name, f.name+"/%/%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Collect all entries
	var allInfos []os.FileInfo
	for rows.Next() {
		var path string
		var mode int
		var size int64
		var isDir bool
		var mtime int64

		if err := rows.Scan(&path, &mode, &size, &isDir, &mtime); err != nil {
			return nil, err
		}

		allInfos = append(allInfos, &FileInfo{
			name:  filepath.Base(path),
			size:  size,
			mode:  os.FileMode(mode),
			mtime: time.Unix(mtime, 0),
			isDir: isDir,
		})
	}

	start := int(f.offset)
	if count <= 0 {
		return allInfos[start:], nil
	}

	end := start + count
	if end > len(allInfos) {
		end = len(allInfos)
	}
	infos := allInfos[start:end]
	f.offset = int64(end)

	if len(infos) == 0 {
		return nil, io.EOF
	}
	return infos, nil
}

func (f *File) Readdirnames(n int) ([]string, error) {
	infos, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(infos))
	for i, info := range infos {
		names[i] = info.Name()
	}

	return names, nil
}

func (f *File) Stat() (os.FileInfo, error) {
	return f.fs.Stat(f.name)
}

func (f *File) Sync() error {
	return f.Close()
}

func (f *File) Truncate(size int64) error {
	if size < 0 {
		return fmt.Errorf("negative size")
	}

	if size == 0 {
		f.data = []byte{}
	} else if size < int64(len(f.data)) {
		f.data = f.data[:size]
	} else {
		newData := make([]byte, size)
		copy(newData, f.data)
		f.data = newData
	}

	f.modified = true
	return nil
}

func (f *File) WriteString(s string) (ret int, err error) {
	return f.Write([]byte(s))
}
