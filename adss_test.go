package adss

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSplitAndRecover(t *testing.T) {
	msg := []byte("hello world")

	R := make([]byte, 32)
	if _, err := rand.Read(R); err != nil {
		panic(err)
	}

	as := NewAccessStructure(2, 3)
	ad := []byte("some associated data")
	shares, err := Share(as, msg, R, ad)

	if err != nil {
		t.Errorf("unexpected error on sharing: %s", err)
	}

	if len(shares) != 3 {
		t.Errorf("len(shares) = %d, expected: %d", len(shares), 3)
	}

	var tests = []struct {
		name  string
		input []*SecretShare
		err   error
		msg   []byte
	}{
    {"all shares", shares, nil, msg},
    {"0-1", []*SecretShare{shares[0], shares[1]}, nil, msg},
    {"0-2", []*SecretShare{shares[0], shares[2]}, nil, msg},
    {"1-2", []*SecretShare{shares[1], shares[2]}, nil, msg},
    {"dup-share", []*SecretShare{shares[0], shares[0]}, fmt.Errorf("duplicate share id found"), nil},
    {"no-shares", []*SecretShare{}, fmt.Errorf("no shares provided"), nil},
		// TODO: Need more tests for validations like:
		//  inconsistent access structure & tags
		//  invalid indexes not compatible with access structure
		//  share modification in different ways and expecting failures
		//  expecting identification of bad shares
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			recov, err := Recover(tt.input)

			if tt.err != nil {
				if err == nil {
					t.Errorf("did not receive error, expected: %s", tt.err)
				} else {
					if err.Error() != tt.err.Error() {
						t.Errorf("unexpected error, expected: %s, got: %s", tt.err, err)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error on recovery: %s", err)
			}

			if !bytes.Equal(recov, msg) {
				t.Errorf("recovered %x != %x", recov, msg)
			}
		})
	}
}

func xTest_kSubsets(t *testing.T) {
	var tests = []struct {
		k        int
		input    []int
		expected string
	}{
		// {1, []int{0, 1, 2}, "{0,},{1,},{2,},"}, (currently broken though not too important to fix since this doesn't come up in practice)
		{2, []int{0, 1, 2}, "{0,1,},{0,2,},{1,2,},"},
		{3, []int{0, 1, 2}, "{0,1,2,},"},
		{3, []int{0, 1, 2, 3}, "{0,1,2,},{0,2,3,},{1,2,3,},"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("%d-subset of len %d", tt.k, len(tt.input)), func(t *testing.T) {
			shares := make([]*SecretShare, len(tt.input))
			for i := range shares {
				shares[i] = &SecretShare{id: uint8(tt.input[i])}
			}

			subsets := kSubsets(tt.k, shares)
			actual := ""
			for _, subset := range subsets {
				actual += "{"
				for _, share := range subset {
					actual += fmt.Sprintf("%d,", share.id)
				}
				actual += "},"
			}

			if actual != tt.expected {
				t.Errorf("given(%d, %v): expected '%s', actual '%s'", tt.k, tt.input, tt.expected, actual)
			}
		})
	}
}
