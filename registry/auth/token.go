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

package auth

// Token is the Bearer token to be used with API calls
type Token interface {
	String() string
	Fresh() bool
}

type token struct {
	val   string
	fresh bool
}

func (t *token) String() string {
	return t.val
}

func (t *token) Fresh() bool {
	return t.fresh
}

func newToken(val string, fresh bool) Token {
	return &token{
		val:   val,
		fresh: fresh,
	}
}
