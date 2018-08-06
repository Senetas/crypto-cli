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

import "io"

// CounterWriter is a writer that counts the number bytes writen to it
type CounterWriter struct {
	io.Writer
	Count int
}

func (cw *CounterWriter) Write(p []byte) (n int, err error) {
	n, err = cw.Writer.Write(p)
	if err != nil {
		return 0, err
	}
	cw.Count += n
	return cw.Count, nil
}

// NoNewlineWriter is a writer that filters out newlines, only '\n'
type NoNewlineWriter struct {
	io.Writer
}

func (nnw *NoNewlineWriter) Write(p []byte) (n int, err error) {
	for _, b := range p {
		if b != '\n' {
			if _, err = nnw.Writer.Write([]byte{b}); err != nil {
				break
			}
			n++
		}
	}
	return n, err
}
