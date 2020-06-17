package adss

import (
	"bytes"
	"testing"
)

func Test_s1SplitAnds1Recover(t *testing.T) {
	msg := []byte("abc")
	shares, err := s1Share(
		NewAccessStructure(2, 3),
		msg,
		[]byte("this is very random"),
		[]byte("some associated data"),
	)

	if err != nil {
		t.Errorf("unexpected error on sharing: %s", err)
	}

	if len(shares) != 3 {
		t.Errorf("len(shares) = %d, expected: %d", len(shares), 3)
	}

	recov, err := s1Recover(shares)
	if err != nil {
		t.Errorf("unexpected error on recovery: %s", err)
	}

	if !bytes.Equal(recov, msg) {
		t.Errorf("recovered %x != %x", recov, msg)
	}
}

// TODO: test validations & error messages
