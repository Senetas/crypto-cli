package utils

import (
	"os"
	"path"
	"path/filepath"
)

// PathTrailingJoin is like path.Join but ensures there is a trailing seprator
func PathTrailingJoin(s ...string) string {
	return path.Join(s...) + "/"
}

// FilePathTrailingJoin is like filepath.Join but ensures there is a trailing seprator
func FilePathTrailingJoin(s ...string) string {
	return filepath.Join(s...) + string(os.PathSeparator)
}
