package adss

import (
	"bytes"
	"testing"
)

func TestSplitAndRecover(t *testing.T) {
	msg := []byte("hello world")
	shares, err := Share(
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

	recov, err := Recover(shares)
	if err != nil {
		t.Errorf("unexpected error on recovery: %s", err)
	}

	if !bytes.Equal(recov, msg) {
		t.Errorf("recovered %x != %x", recov, msg)
	}
}

// TODO: Other test cases, modifying data accordingly and ensuring we see failures on reconstruct.
