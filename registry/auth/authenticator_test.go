package auth_test

import (
	"net/http"
	"testing"

	"github.com/Senetas/crypto-cli/registry/auth"
)

func TestAuthenticator(t *testing.T) {
	creds := auth.NewDefaultCreds()
	a := auth.NewAuthenticator(http.DefaultClient, creds)
	ch, err := auth.ParseChallengeHeader(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:narthanaepa1:pull,push"`)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.Authenticate(ch)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tok)
}
