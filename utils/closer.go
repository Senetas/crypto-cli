package utils

import (
	"io"
)

// CheckedClose may be called on defer to properly close a resouce and log any errors
func CheckedClose(c io.Closer) error {
	if err := c.Close(); err != nil {
		return err
	}
	return nil
}
