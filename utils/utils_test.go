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

package utils_test

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Senetas/crypto-cli/utils"
)

func TestCloser(t *testing.T) {
	assert := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		closer *MockCloser
		inErr  error
		retVal error
		result string
	}{
		{NewMockCloser(ctrl), nil, nil, ""},
		{NewMockCloser(ctrl), nil, errors.New("new error"), "new error"},
		{NewMockCloser(ctrl), errors.New("old error"), nil, "old error"},
		{NewMockCloser(ctrl), errors.New("old error"), errors.New("new error"), "old error\nnew error"},
	}

	for _, test := range tests {
		test.closer.EXPECT().Close().Return(test.retVal)
		err := utils.CheckedClose(test.closer, test.inErr)
		if err != nil {
			assert.EqualError(err, test.result)
		}
	}
}

func TestConcat(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		in  [][]byte
		out []byte
	}{
		{[][]byte{[]byte("3.14"), []byte("159")}, []byte("3.14159")},
		{[][]byte{{}, []byte("159")}, []byte("159")},
		{[][]byte{[]byte("3.14"), {}}, []byte("3.14")},
		{[][]byte{{}, {}}, []byte{}},
		{[][]byte{[]byte("3.14"), []byte("159"), []byte("265")}, []byte("3.14159265")},
	}

	for _, test := range tests {
		out := utils.Concat(test.in)
		assert.Equal(out, test.out)
	}
}

func TestPathTrailingJoin(t *testing.T) {
	path := utils.PathTrailingJoin("path/", "to", "file/")
	require.Equal(t, path, "path/to/file/")
}

func TestFilePathTrailingJoin(t *testing.T) {
	path := utils.FilePathTrailingJoin("path/", "to", "file/")
	require.Equal(
		t,
		path,
		"path"+string(os.PathSeparator)+"to"+string(os.PathSeparator)+"file"+string(os.PathSeparator),
	)
}

func TestFilePathSansExt(t *testing.T) {
	path := utils.FilePathSansExt("path/to/file.text")
	require.Equal(
		t,
		path,
		"path"+string(os.PathSeparator)+"to"+string(os.PathSeparator)+"file",
	)
}

type mockBuffer interface {
	Bytes() []byte
	Write(p []byte) (int, error)
}

type errWriter byte

func newErrWriter() (e *errWriter) {
	return
}

func (*errWriter) Write(p []byte) (int, error) {
	return 0, errors.New("mock write error")
}

func (*errWriter) Bytes() []byte {
	return []byte{}
}

func TestCounterWriter(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		in  []byte
		out mockBuffer
	}{
		{[]byte("0123456789"), &bytes.Buffer{}},
		{[]byte("0123456789"), newErrWriter()},
	}

	for _, test := range tests {
		r := bytes.NewReader(test.in)
		w := &utils.CounterWriter{Writer: test.out}
		_, err := io.Copy(w, r)
		if err != nil {
			assert.EqualError(err, "mock write error")
			continue
		}
		_ = assert.Equal(test.in, test.out.Bytes()) && assert.Equal(w.Count, len(test.in))
	}
}

func TestNoNewlineWriter(t *testing.T) {
	assert := assert.New(t)

	correct := []byte("0123456789")
	in := []byte("\n01234\n56789\n")
	r := bytes.NewReader(in)
	out := bytes.Buffer{}
	cw := &utils.CounterWriter{Writer: &out}
	w := utils.NewNoNewlineWriter(cw)

	// io.Copy does not return the right number of written bytes
	_, err := io.Copy(w, r)
	_ = assert.NoError(err) && assert.Equal(len(correct), cw.Count) && assert.Equal(correct, out.Bytes())
}

func TestResetReader(t *testing.T) {
	assert := assert.New(t)
	correct := []byte("01234567890")
	r := bytes.NewReader(correct)
	trr := utils.NewResetReader(r, func() { t.Log("Hello") })
	out := &bytes.Buffer{}
	n, err := io.Copy(out, trr)
	_ = assert.NoError(err) && assert.Equal(len(correct), int(n)) && assert.Equal(correct, out.Bytes())
}

func TestLargeResetReader(t *testing.T) {
	assert := assert.New(t)

	dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	defer func() { assert.NoError(os.RemoveAll(dir)) }()

	if err := os.MkdirAll(dir, 0700); !assert.NoError(err) {
		return
	}

	zr := utils.ConstReader(1)
	trr := utils.NewResetReader(zr, func() { t.Log("Hello") })

	fh, err := os.Create(filepath.Join(dir, "file"))
	if !assert.NoError(err) {
		return
	}

	N := 1024*1024 + 121
	n, err := io.CopyN(fh, trr, int64(N))

	_ = !assert.NoError(err) && assert.Equal(N, int(n))
}

func TestError(t *testing.T) {
	assert := assert.New(t)
	err := errors.New("an error")

	err = utils.WrapError(err, true)
	e, ok := err.(utils.Error)
	if assert.True(ok) {
		assert.True(e.HasStack)
	}

	err = utils.StripTrace(err)
	if e, ok = err.(utils.Error); assert.True(ok) {
		assert.False(e.HasStack)
	}
}

func TestErrors(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		errs utils.Errors
		msg  string
	}{
		{utils.Errors{}, ""},
		{utils.Errors{errors.New("hello")}, "hello"},
	}

	for _, test := range tests {
		assert.True(test.errs.Error() == test.msg)
	}
}

func TestConcatErrChan(t *testing.T) {
	assert := assert.New(t)

	for n := 0; n < 3; n++ {
		errCh := make(chan error, n)
		for i := 0; i < n; i++ {
			go func(i int) { errCh <- errors.Errorf("%d", i) }(i)
		}
		err := utils.ConcatErrChan(errCh, n)
		for i := 0; i < n; i++ {
			assert.True(strings.Contains(err.Error(), fmt.Sprintf("%d", i)))
		}
	}
}

func TestUint64ToPosInt(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		i      uint64
		o      int
		errMsg string
	}{
		{0, 0, ""},
		{238746, 238746, ""},
		{math.MaxInt32, math.MaxInt32, ""},
		{math.MaxUint64, 0, "expected positive integer"},
	}

	for _, test := range tests {
		o, err := utils.Uint64ToPosInt(test.i)
		if err != nil {
			assert.EqualError(err, test.errMsg)
		} else { // expecting an error?
			assert.Equal("", test.errMsg)
			assert.Equal(test.o, o)
		}
	}
}

func TestCheckedClose(t *testing.T) {
	tests := []struct {
		errIn  error
		errOut error
		c      io.Closer
	}{
		{nil, nil, nil},
	}

	for _, test := range tests {
		err := utils.CheckedClose(test.c, test.errIn)
		assert.Equal(t, test.errOut, err)
	}
}

func TestCleanUp(t *testing.T) {
	assert := assert.New(t)

	var (
		errorRemove = func(s string) error { return errors.New("internal error") }
		dir         = filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	)

	tests := []struct {
		remove func(s string) error
		dir    string
		errIn  error
		errMsg string
	}{
		{utils.RemoveFunc, dir, nil, ""},
		{utils.RemoveFunc, "", errors.New("an error"), "an error"},
		{
			errorRemove,
			dir,
			nil,
			fmt.Sprintf(`could not clean up temp files in: %s: internal error`, dir),
		},
		{
			errorRemove,
			dir,
			errors.New("external error"),
			fmt.Sprintf(`could not clean up temp files in: %s: internal error: external error`, dir),
		},
	}

	for _, test := range tests {
		utils.RemoveFunc = test.remove
		err := utils.CleanUp(test.dir, test.errIn)
		if err != nil {
			assert.EqualError(err, test.errMsg)
		} else {
			assert.Equal("", test.errMsg)
		}
	}
}
