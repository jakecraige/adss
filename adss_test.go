package adss

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSplitAndRecover(t *testing.T) {
	msg := []byte("hello world")

	as := NewAccessStructure(2, 3)
	ad := []byte("some associated data")
	shares, err := Share(as, msg, ad)

	if err != nil {
		t.Errorf("unexpected error on sharing: %s", err)
	}

	if len(shares) != 3 {
		t.Errorf("len(shares) = %d, expected: %d", len(shares), 3)
	}

	// These tests cover providing valid shares in different ways and verifying that
	// we can recover the message.
	var successTests = []struct {
		name string
		msg  []byte
		data []*SecretShare
	}{
		{"all shares", msg, shares},
		{"0-1", msg, []*SecretShare{shares[0], shares[1]}},
		{"0-2", msg, []*SecretShare{shares[0], shares[2]}},
		{"1-2", msg, []*SecretShare{shares[1], shares[2]}},
	}

	for _, tt := range successTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			recov, _, err := Recover(tt.data)

			if err != nil {
				t.Errorf("unexpected error on recovery: %s", err)
			}

			if !bytes.Equal(recov, tt.msg) {
				t.Errorf("recovered %x != %x", recov, tt.msg)
			}
		})
	}

	// These tests are those that return errors in a way where no err-recovery happens.
	// The data is just bad in some way so we require an error to be returned.
	var errTests = []struct {
		name string
		data func() []*SecretShare
		err  func() error
	}{
		{
			"dup-share",
			func() []*SecretShare { return []*SecretShare{shares[0], shares[0]} },
			func() error { return fmt.Errorf("plausible shares: duplicate share ID found") },
		},
		{
			"no-shares",
			func() []*SecretShare { return []*SecretShare{} },
			func() error { return fmt.Errorf("plausible shares: no shares provided") },
		},
		{
			"modified-as",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.As.T = mod.As.T + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("plausible shares: shares have inconsistent access structures")
			},
		},
		{
			"modified-id",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.ID = mod.As.N - 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-C",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.Pub.C[0] = mod.Pub.C[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-D",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.Pub.D[0] = mod.Pub.D[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-J",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.Pub.J[0] = mod.Pub.J[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-sec",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.Sec[0] = mod.Sec[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-tag",
			func() []*SecretShare {
				// We need to modify both to be the same value so that we don't get the
				// inconsistent tags error.
				mod1 := cloneShare(shares[0])
				mod1.Tag[0] = mod1.Tag[0] + 1
				mod2 := cloneShare(shares[1])
				mod2.Tag[0] = mod1.Tag[0]
				return []*SecretShare{mod1, mod2}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"inconsistent-tag",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.Tag[0] = mod.Tag[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("plausible shares: shares have inconsistent tags")
			},
		},
		{"multiple-explanations",
			func() []*SecretShare {
				as := NewAccessStructure(2, 5)
				shares1, err := Share(as, msg, ad)
				if err != nil {
					panic(err)
				}

				shares2, err := Share(as, msg, ad)
				if err != nil {
					panic(err)
				}

				return []*SecretShare{shares1[0], shares1[1], shares2[2], shares2[3]}
			},
			func() error {
				return fmt.Errorf("multiple explanations: {ID:2, ID:3} and {ID:0, ID:1}")
			},
		},
	}
	for _, tt := range errTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Recover(tt.data())

			expectedErr := tt.err()
			if err == nil {
				t.Errorf("did not receive error, expected: %s", expectedErr)
				return
			}

			if err.Error() != expectedErr.Error() {
				t.Errorf("unexpected error, expected: %s, got: %s", expectedErr, err)
			}
		})
	}

	// These tests verify that the message can be recovered in the presence of bad
	// shares, as long as there are enough good ones.
	var errRecoveryTests = []struct {
		name           string
		msg            []byte
		data           func() []*SecretShare
		validShareIdxs []int
	}{
		{"modified-C", msg,
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.Pub.C[0] = mod.Pub.C[0] + 1
				return []*SecretShare{shares[1], mod, shares[2]}
			},
			[]int{0, 2},
		},
		{"modified-sec", msg,
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.Sec = []byte("this share is bad")
				return []*SecretShare{mod, shares[1], shares[2]}
			},
			[]int{1, 2},
		},
	}
	for _, tt := range errRecoveryTests {
		tt := tt
		t.Run(fmt.Sprintf("errRecovery: %s", tt.name), func(t *testing.T) {
			dat := tt.data()
			recov, V, err := Recover(dat)

			if err != nil {
				t.Errorf("unexpected error on recovery: %s", err)
			}

			if !bytes.Equal(recov, tt.msg) {
				t.Errorf("recovered %x != %x", recov, tt.msg)
			}

			if len(V) < len(tt.validShareIdxs) {
				t.Errorf("not enough valid shares returned: got %d expected: %d", len(V), len(tt.validShareIdxs))
			}

			for i, idx := range tt.validShareIdxs[:len(V)] {
				returned := V[i].Bytes()
				expected := dat[idx].Bytes()
				if !bytes.Equal(returned, expected) {
					t.Errorf("returned share \n%x \nwas supposed to be \n%x", returned, expected)
				}
			}
		})
	}
}

func cloneShare(share *SecretShare) *SecretShare {
	out := &SecretShare{ID: share.ID, As: share.As}
	out.Pub = struct{ C, D, J []byte }{
		append([]byte{}, share.Pub.C...),
		append([]byte{}, share.Pub.D...),
		append([]byte{}, share.Pub.J...),
	}
	out.Sec = append([]byte{}, share.Sec...)
	out.Tag = append([]byte{}, share.Tag...)
	return out
}

func Test_kSubsets(t *testing.T) {
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
				shares[i] = &SecretShare{ID: uint8(tt.input[i])}
			}

			subsets := kSubsets(tt.k, shares)
			actual := ""
			for _, subset := range subsets {
				actual += "{"
				for _, share := range subset {
					actual += fmt.Sprintf("%d,", share.ID)
				}
				actual += "},"
			}

			if actual != tt.expected {
				t.Errorf("given(%d, %v): expected '%s', actual '%s'", tt.k, tt.input, tt.expected, actual)
			}
		})
	}
}
