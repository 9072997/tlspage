package sqlitefs

import (
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"

	_ "modernc.org/sqlite"
)

// getTestFs returns a new Fs for testing, using an in-memory SQLite DB.
func getTestFs(t *testing.T) (*Fs, *sql.DB) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	fs, err := New(db, "testfs")
	if err != nil {
		dump(db, t)
		t.Fatalf("failed to create test fs: %v", err)
	}
	return fs, db
}

func TestCreateAndOpenFile(t *testing.T) {
	fs, db := getTestFs(t)
	f, err := fs.Create("foo.txt")
	if err != nil {
		dump(db, t)
		t.Fatalf("Create failed: %v", err)
	}
	defer f.Close()

	n, err := f.Write([]byte("hello"))
	if err != nil || n != 5 {
		dump(db, t)
		t.Fatalf("Write failed: %v, n=%d", err, n)
	}
	f.Sync()
	f.Close()

	f2, err := fs.Open("foo.txt")
	if err != nil {
		dump(db, t)
		t.Fatalf("Open failed: %v", err)
	}
	defer f2.Close()
	buf := make([]byte, 10)
	n, err = f2.Read(buf)
	if err != nil && err != io.EOF {
		dump(db, t)
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "hello" {
		dump(db, t)
		t.Errorf("Read got %q, want %q", buf[:n], "hello")
	}
}

func TestMkdirAndStat(t *testing.T) {
	fs, db := getTestFs(t)
	err := fs.Mkdir("dir", 0755)
	if err != nil {
		dump(db, t)
		t.Fatalf("Mkdir failed: %v", err)
	}
	info, err := fs.Stat("dir")
	if err != nil {
		dump(db, t)
		t.Fatalf("Stat failed: %v", err)
	}
	if !info.IsDir() {
		dump(db, t)
		t.Errorf("Stat: expected directory")
	}
}

func TestMkdirAll(t *testing.T) {
	fs, db := getTestFs(t)
	err := fs.MkdirAll("a/b/c", 0755)
	if err != nil {
		dump(db, t)
		t.Fatalf("MkdirAll failed: %v", err)
	}
	for _, d := range []string{"a", filepath.Join("a", "b"), filepath.Join("a", "b", "c")} {
		info, err := fs.Stat(d)
		if err != nil || !info.IsDir() {
			dump(db, t)
			t.Errorf("Stat(%q) failed or not dir: %v", d, err)
		}
	}
}

func TestRemoveAndRemoveAll(t *testing.T) {
	fs, db := getTestFs(t)
	fs.MkdirAll("x/y", 0755)
	f, _ := fs.Create("x/y/z.txt")
	f.Close()
	err := fs.Remove("x/y/z.txt")
	if err != nil {
		dump(db, t)
		t.Fatalf("Remove failed: %v", err)
	}
	_, err = fs.Stat("x/y/z.txt")
	if !os.IsNotExist(err) {
		dump(db, t)
		t.Errorf("Stat after Remove: want not exist, got %v", err)
	}
	err = fs.RemoveAll("x")
	if err != nil {
		dump(db, t)
		t.Fatalf("RemoveAll failed: %v", err)
	}
	_, err = fs.Stat("x")
	if !os.IsNotExist(err) {
		dump(db, t)
		t.Errorf("Stat after RemoveAll: want not exist, got %v", err)
	}
}

func TestRename(t *testing.T) {
	fs, db := getTestFs(t)
	f, _ := fs.Create("old.txt")
	f.WriteString("data")
	f.Close()
	err := fs.Rename("old.txt", "new.txt")
	if err != nil {
		dump(db, t)
		t.Fatalf("Rename failed: %v", err)
	}
	_, err = fs.Stat("old.txt")
	if !os.IsNotExist(err) {
		dump(db, t)
		t.Errorf("Old file still exists after rename")
	}
	info, err := fs.Stat("new.txt")
	if err != nil || info.IsDir() {
		dump(db, t)
		t.Errorf("New file missing or is dir: %v", err)
	}
}

func TestChmodChownChtimes(t *testing.T) {
	fs, db := getTestFs(t)
	f, _ := fs.Create("file.txt")
	f.Close()
	err := fs.Chmod("file.txt", 0600)
	if err != nil {
		dump(db, t)
		t.Fatalf("Chmod failed: %v", err)
	}
	// Chown is a no-op on Windows, but should not error
	err = fs.Chown("file.txt", 1, 2)
	if err != nil {
		dump(db, t)
		t.Fatalf("Chown failed: %v", err)
	}
	atime := time.Now().Add(-time.Hour)
	mtime := time.Now().Add(-time.Minute)
	err = fs.Chtimes("file.txt", atime, mtime)
	if err != nil {
		dump(db, t)
		t.Fatalf("Chtimes failed: %v", err)
	}
}

func TestReaddirAndReaddirnames(t *testing.T) {
	fs, db := getTestFs(t)
	err := fs.MkdirAll("dir", 0755)
	if err != nil {
		dump(db, t)
		t.Fatalf("MkdirAll failed: %v", err)
	}
	f1, err := fs.Create("dir/a.txt")
	if err != nil {
		dump(db, t)
		t.Fatalf("Create a.txt failed: %v", err)
	}
	f1.Close()
	f2, err := fs.Create("dir/b.txt")
	if err != nil {
		dump(db, t)
		t.Fatalf("Create b.txt failed: %v", err)
	}
	f2.Close()
	d, err := fs.Open("dir")
	if err != nil {
		dump(db, t)
		t.Fatalf("Open dir failed: %v", err)
	}
	defer d.Close()
	infos, err := d.Readdir(0)
	if err != nil {
		dump(db, t)
		t.Fatalf("Readdir failed: %v", err)
	}
	if len(infos) < 2 {
		dump(db, t)
		t.Errorf("Readdir: want at least 2 files, got %d", len(infos))
	}
	names, err := d.Readdirnames(0)
	if err != nil {
		dump(db, t)
		t.Fatalf("Readdirnames failed: %v", err)
	}
	if len(names) < 2 {
		dump(db, t)
		t.Errorf("Readdirnames: want at least 2 files, got %d", len(names))
	}
}

func TestReaddirEmptyDir(t *testing.T) {
	fs, db := getTestFs(t)
	err := fs.Mkdir("empty", 0755)
	if err != nil {
		dump(db, t)
		t.Fatalf("Mkdir failed: %v", err)
	}
	d, err := fs.Open("empty")
	if err != nil {
		dump(db, t)
		t.Fatalf("Open empty dir failed: %v", err)
	}
	defer d.Close()
	infos, err := d.Readdir(0)
	if err != nil {
		dump(db, t)
		t.Fatalf("Readdir on empty dir failed: %v", err)
	}
	if len(infos) != 0 {
		dump(db, t)
		t.Errorf("Readdir on empty dir: got %d entries, want 0", len(infos))
	}
}

func TestReaddirWithOffset(t *testing.T) {
	fs, db := getTestFs(t)
	err := fs.MkdirAll("testdir", 0755)
	if err != nil {
		dump(db, t)
		t.Fatalf("MkdirAll failed: %v", err)
	}
	for i := '0'; i <= '9'; i++ {
		f, err := fs.Create(filepath.Join("testdir", "file"+string(i)+".txt"))
		if err != nil {
			dump(db, t)
			t.Fatalf("Create file%c failed: %v", i, err)
		}
		f.Close()
	}
	d, err := fs.Open("testdir")
	if err != nil {
		dump(db, t)
		t.Fatalf("Open testdir failed: %v", err)
	}
	defer d.Close()
	// Read entries 7 at a time. Should get 7, then 3, then EOF.
	infos, err := d.Readdir(7)
	if err != nil {
		dump(db, t)
		t.Fatalf("Readdir failed: %v", err)
	}
	if len(infos) != 7 {
		dump(db, t)
		t.Errorf("Readdir: got %d entries, want 7", len(infos))
	}
	infos, err = d.Readdir(7)
	if err != nil {
		dump(db, t)
		t.Fatalf("Readdir failed: %v", err)
	}
	if len(infos) != 3 {
		dump(db, t)
		t.Errorf("Readdir: got %d entries, want 3", len(infos))
	}
	infos, err = d.Readdir(7)
	if err != nil && err != io.EOF {
		dump(db, t)
		t.Fatalf("Readdir failed: %v", err)
	}
	if len(infos) != 0 {
		dump(db, t)
		t.Errorf("Readdir: got %d entries, want 0", len(infos))
	}
}

// this is more of a compile time test, but just make sure we can cast to
// affero.FS
func TestCasts(t *testing.T) {
	var afferoFs afero.Fs = new(Fs)
	var afferoFile afero.File = new(File)
	var osFileInfo os.FileInfo = new(FileInfo)
	_ = afferoFs
	_ = afferoFile
	_ = osFileInfo
}

// utility to dump an in-memory database to disk for inspection
func dump(db *sql.DB, t *testing.T) {
	filename := filepath.Join(os.TempDir(), "sqlitefs_dump.db")
	// delete any existing dump file
	err := os.Remove(filename)
	if err != nil && !os.IsNotExist(err) {
		t.Logf("Failed to remove existing dump file: %v", err)
		return
	}

	_, err = db.Exec("VACUUM INTO ?", filename)
	if err != nil {
		t.Logf("Failed to dump DB: %v", err)
		return
	}
	t.Logf("Database dumped to %s", filename)
}
