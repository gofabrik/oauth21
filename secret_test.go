package oauth21_test

import (
	"strings"
	"testing"

	"github.com/gofabrik/oauth21"
)

func TestPBKDF2KnownAnswer(t *testing.T) {
	hash := "$pbkdf2-sha256$1$c2FsdA$Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs"
	if !(oauth21.PBKDF2{}).Verify(hash, "password") {
		t.Fatal("got the published PBKDF2-HMAC-SHA256 test vector rejected")
	}
	if (oauth21.PBKDF2{}).Verify(hash, "passwore") {
		t.Fatal("got a wrong secret accepted")
	}
}

func TestPBKDF2Hash(t *testing.T) {
	h := oauth21.PBKDF2{Iterations: 1000}
	first, err := h.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("got the same hash twice, want a fresh salt")
	}
	if !h.Verify(first, "secret") || h.Verify(first, "Secret") || h.Verify(first, "") {
		t.Fatalf("got %q verifying the wrong secrets", first)
	}
}

func TestPBKDF2DefaultIterations(t *testing.T) {
	hash, err := oauth21.PBKDF2{}.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$pbkdf2-sha256$600000$") {
		t.Fatalf("got hash %q, want 600000 iterations", hash)
	}
}

func TestPBKDF2RejectsMalformedHash(t *testing.T) {
	for _, hash := range []string{
		"",
		"$pbkdf2-sha256$1$c2FsdA",
		"$pbkdf2-sha1$1$c2FsdA$Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs",
		"$pbkdf2-sha256$0$c2FsdA$Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs",
		"$pbkdf2-sha256$x$c2FsdA$Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs",
		"$pbkdf2-sha256$1$c2FsdA$!",
		"$pbkdf2-sha256$1$c2FsdA$",
		"$pbkdf2-sha256$1$c2FsdA$Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs$",
	} {
		if (oauth21.PBKDF2{}).Verify(hash, "password") {
			t.Errorf("%q: got the secret accepted", hash)
		}
	}
}
