// Copyright © 2018 SENETAS SECURITY PTY LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"bytes"
	"io"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/rangetable"
)

// CounterWriter is a writer that counts the number bytes writen to it
type CounterWriter struct {
	io.Writer
	Count int
}

func (cw *CounterWriter) Write(p []byte) (n int, err error) {
	n, err = cw.Writer.Write(p)
	if err != nil {
		return
	}
	cw.Count += n
	return
}

// NewNoNewlineWriter wrap a writer and filters out '\n' runes
func NewNoNewlineWriter(w io.Writer) io.Writer {
	t := runes.Remove(runes.In(rangetable.New('\n')))
	return transform.NewWriter(w, t)
}

// ResetReader is an io.Reader that reads from r and calls
// resetfn every time Read() is called
type ResetReader struct {
	reader  io.Reader
	resetfn func()
}

// NewResetReader creates a new ResetReader that reads from r and calls
// resetfn every time Read() is called
func NewResetReader(r io.Reader, f func()) *ResetReader {
	return &ResetReader{
		reader:  r,
		resetfn: f,
	}
}

func (trr *ResetReader) Read(p []byte) (n int, err error) {
	b := &bytes.Buffer{}
	m, err := io.CopyN(b, trr.reader, int64(len(p)))
	copy(p, b.Bytes())
	n += int(m)
	trr.resetfn()
	return
}

// ConstReader is a stream of a constant byte
type ConstReader byte

func (r ConstReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(r)
	}
	return len(b), nil
}
