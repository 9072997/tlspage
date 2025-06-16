package mountfs

import (
	"os"
	"path"
	"strings"
	"time"

	"github.com/spf13/afero"
)

// Fs allows mounting multiple filesystems at different path prefixes.
type Fs struct {
	// key: mount point (must be cleaned, absolute, no trailing slash), value: Fs
	mounts map[string]afero.Fs
}

// New creates a new MountFs.
func New() *Fs {
	return &Fs{mounts: make(map[string]afero.Fs)}
}

// Mount mounts an Fs at the given mount point (e.g., "/foo").
func (m *Fs) Mount(mountPoint string, fs afero.Fs) {
	mountPoint = path.Clean(mountPoint)
	m.mounts[mountPoint] = fs
}

// findMount finds the most specific mount for the given path.
func (m *Fs) findMount(name string) (afero.Fs, string, string) {
	name = path.Clean(name)
	var bestMount string
	for mount := range m.mounts {
		if mount == "/" || strings.HasPrefix(name, mount+"/") || name == mount {
			if len(mount) > len(bestMount) {
				bestMount = mount
			}
		}
	}
	fs := m.mounts[bestMount]
	rel := strings.TrimPrefix(name, bestMount)
	if rel == "" {
		rel = "."
	} else if rel[0] == '/' {
		rel = rel[1:]
	}
	return fs, bestMount, rel
}

// Implement Fs interface:

func (m *Fs) Create(name string) (afero.File, error) {
	fs, _, rel := m.findMount(name)
	return fs.Create(rel)
}
func (m *Fs) Mkdir(name string, perm os.FileMode) error {
	fs, _, rel := m.findMount(name)
	return fs.Mkdir(rel, perm)
}
func (m *Fs) MkdirAll(path string, perm os.FileMode) error {
	fs, _, rel := m.findMount(path)
	return fs.MkdirAll(rel, perm)
}
func (m *Fs) Open(name string) (afero.File, error) {
	fs, _, rel := m.findMount(name)
	return fs.Open(rel)
}
func (m *Fs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	fs, _, rel := m.findMount(name)
	return fs.OpenFile(rel, flag, perm)
}
func (m *Fs) Remove(name string) error {
	fs, _, rel := m.findMount(name)
	return fs.Remove(rel)
}
func (m *Fs) RemoveAll(path string) error {
	fs, _, rel := m.findMount(path)
	return fs.RemoveAll(rel)
}
func (m *Fs) Rename(oldname, newname string) error {
	oldfs, _, oldrel := m.findMount(oldname)
	newfs, _, newrel := m.findMount(newname)
	if oldfs != newfs {
		return os.ErrInvalid // can't rename across mounts
	}
	return oldfs.Rename(oldrel, newrel)
}
func (m *Fs) Stat(name string) (os.FileInfo, error) {
	fs, _, rel := m.findMount(name)
	return fs.Stat(rel)
}
func (m *Fs) Name() string { return "MountFs" }
func (m *Fs) Chmod(name string, mode os.FileMode) error {
	fs, _, rel := m.findMount(name)
	return fs.Chmod(rel, mode)
}
func (m *Fs) Chown(name string, uid, gid int) error {
	fs, _, rel := m.findMount(name)
	return fs.Chown(rel, uid, gid)
}
func (m *Fs) Chtimes(name string, atime, mtime time.Time) error {
	fs, _, rel := m.findMount(name)
	return fs.Chtimes(rel, atime, mtime)
}
