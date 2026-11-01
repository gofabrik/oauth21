package oauth21

import (
	"strconv"
	"testing"
	"time"
)

func TestLockoutsAreSweptAfterDuration(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newLockouts(Lockout{Failures: 5, Duration: time.Minute}, func() time.Time { return now })
	for i := range 2000 {
		key := lockoutKey{client: "client", source: strconv.Itoa(i)}
		if !l.begin(t.Context(), key) {
			t.Fatal("got a first attempt refused")
		}
		l.end(key, false)
	}
	now = now.Add(time.Minute)
	key := lockoutKey{client: "client", source: "late"}
	l.begin(t.Context(), key)
	l.end(key, false)
	if n := len(l.byKey); n != 1 {
		t.Fatalf("got %d sources kept a minute after their failures, want only the late one", n)
	}
}

func TestLockoutsForgetSuccessWithoutFailures(t *testing.T) {
	l := newLockouts(Lockout{Failures: 5, Duration: time.Minute}, time.Now)
	key := lockoutKey{client: "client", source: "source"}
	l.begin(t.Context(), key)
	l.end(key, true)
	if n := len(l.byKey); n != 0 {
		t.Fatalf("got %d sources kept after a success without failures, want none", n)
	}
}
