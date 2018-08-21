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

// ResetReader is a reader that resets a timer every time it reads some
// number of bytes
type ResetReader struct {
	reader        io.Reader
	resetfn       func()
	copied, reset int
}

// NewResetReader creates a new TimerResetReader that reads from r and
// resets the timer t after every "resetEvery" bytes read
func NewResetReader(r io.Reader, reset int, f func()) *ResetReader {
	return &ResetReader{
		reader:  r,
		reset:   reset,
		resetfn: f,
	}
}

func (trr *ResetReader) Read(p []byte) (n int, err error) {
	var i, m int64
	b := &bytes.Buffer{}

	// copy reset bytes at a time, reseting the timer each time
	for ; i < int64(len(p)-trr.reset); i = i + m {
		m, err = io.CopyN(b, trr.reader, int64(trr.reset))
		n += copy(p[i:i+m], b.Bytes())
		if err != nil {
			return
		}

		trr.copied = (trr.copied + int(m)) % trr.reset
		trr.resetfn()
		b.Reset()
	}

	// take care of left overs, reset if we cross a multiple of reset
	m, err = io.CopyN(b, trr.reader, int64(len(p)%trr.reset))
	n += copy(p[i:i+m], b.Bytes())
	if err != nil {
		return
	}
	trr.copied += int(m)
	if trr.copied >= trr.reset {
		trr.copied %= trr.reset
		trr.resetfn()
	}

	return n, nil
}
