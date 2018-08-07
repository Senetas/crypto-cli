package names_test

import (
	_ "crypto/sha256"
	"fmt"
	"testing"

	"github.com/docker/distribution/reference"
	digest "github.com/opencontainers/go-digest"

	"github.com/Senetas/crypto-cli/registry/names"
)

const (
	domain        = "localhost:5000"
	defaultDomain = "docker.io"
	repo          = "hello/alpine"
	tag           = "atag"
	defaultTag    = "latest"
)

func TestTrimedNamed(t *testing.T) {
	ref, err := reference.ParseNamed(fmt.Sprintf("%s/%s:%s", domain, repo, tag))
	if err != nil {
		t.Fatal(err)
	}

	trimed := names.TrimNamed(ref)

	if trimed.Domain() != domain {
		t.Fatalf("domain is %s, should be %s", trimed.Domain(), domain)
	}

	if trimed.Path() != repo {
		t.Fatalf("path is %s, should be %s", trimed.Path(), repo)
	}
}

func TestSeperateRepository(t *testing.T) {
	ref, err := reference.ParseNamed(fmt.Sprintf("%s/%s:%s", domain, repo, tag))
	if err != nil {
		t.Fatal(err)
	}

	sep := names.SeperateRepository(ref)

	if sep.Domain() != domain {
		t.Fatalf("domain is %s, should be %s", sep.Domain(), domain)
	}

	if sep.Path() != repo {
		t.Fatalf("path is %s, should be %s", sep.Path(), repo)
	}

	if sep.Name() != repo {
		t.Fatalf("name is %s, should be %s", sep.Name(), repo)
	}

	ref, err = reference.ParseNormalizedNamed(fmt.Sprintf("%s:%s", repo, tag))
	if err != nil {
		t.Fatal(err)
	}

	sep = names.SeperateRepository(ref)

	if sep.Domain() != defaultDomain {
		t.Fatalf("domain is %s, should be %s", sep.Domain(), defaultDomain)
	}

	if sep.Path() != repo {
		t.Fatalf("path is %s, should be %s", sep.Path(), repo)
	}

	if sep.Name() != repo {
		t.Fatalf("name is %s, should be %s", sep.Name(), repo)
	}
}

func TestSeperateTaggedRepository(t *testing.T) {
	ref, err := reference.ParseNamed(fmt.Sprintf("%s/%s", domain, repo))
	if err != nil {
		t.Fatal(err)
	}

	tagged, err := reference.WithTag(ref, tag)
	if err != nil {
		t.Fatal(err)
	}

	sep := names.SeperateTaggedRepository(tagged)

	if sep.Domain() != domain {
		t.Fatalf("domain is %s, should be %s", sep.Domain(), domain)
	}

	if sep.Path() != repo {
		t.Fatalf("path is %s, should be %s", sep.Path(), repo)
	}

	if sep.Name() != repo {
		t.Fatalf("name is %s, should be %s", sep.Name(), repo)
	}

	if sep.Tag() != tag {
		t.Fatalf("tag is %s, should be %s", sep.Tag(), tag)
	}
}

func TestCastToTagged(t *testing.T) {
	ref, err := reference.ParseNamed(fmt.Sprintf("%s/%s", domain, repo))
	if err != nil {
		t.Fatal(err)
	}

	cast, err := names.CastToTagged(ref)
	if err != nil {
		t.Fatal(err)
	}

	if cast.Domain() != domain {
		t.Fatalf("domain is %s, should be %s", cast.Domain(), domain)
	}

	if cast.Path() != repo {
		t.Fatalf("path is %s, should be %s", cast.Path(), repo)
	}

	if cast.Name() != repo {
		t.Fatalf("name is %s, should be %s", cast.Name(), repo)
	}

	if cast.Tag() != defaultTag {
		t.Fatalf("tag is %s, should be %s", cast.Tag(), defaultTag)
	}

	ref, err = reference.ParseNamed(fmt.Sprintf("%s/%s:%s", domain, repo, tag))
	if err != nil {
		t.Fatal(err)
	}

	cast, err = names.CastToTagged(ref)
	if err != nil {
		t.Fatal(err)
	}

	if cast.Domain() != domain {
		t.Fatalf("domain is %s, should be %s", cast.Domain(), domain)
	}

	if cast.Path() != repo {
		t.Fatalf("path is %s, should be %s", cast.Path(), repo)
	}

	if cast.Name() != repo {
		t.Fatalf("name is %s, should be %s", cast.Name(), repo)
	}

	if cast.Tag() != tag {
		t.Fatalf("tag is %s, should be %s", cast.Tag(), tag)
	}
}

func TestAppendDigest(t *testing.T) {
	ref, err := reference.ParseNamed(fmt.Sprintf("%s/%s", domain, repo))
	if err != nil {
		t.Fatal(err)
	}

	sep := names.SeperateRepository(ref)
	d := digest.Canonical.FromString("foobar")
	dig := names.AppendDigest(sep, d)

	if dig.Name() != repo {
		t.Fatalf("name is %s, should be %s", dig.Name(), repo)
	}

	if dig.Digest() != d {
		t.Fatalf("tag is %s, should be %s", dig.Digest(), d)
	}
}
