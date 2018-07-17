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
