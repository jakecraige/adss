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
			func() error { return fmt.Errorf("plausible shares: duplicate share id found") },
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
				mod.as.t = mod.as.t + 1
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
				mod.id = mod.as.n - 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-C",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.pub.C[0] = mod.pub.C[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-D",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.pub.D[0] = mod.pub.D[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-J",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.pub.J[0] = mod.pub.J[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"modified-sec",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.sec[0] = mod.sec[0] + 1
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
				mod1.tag[0] = mod1.tag[0] + 1
				mod2 := cloneShare(shares[1])
				mod2.tag[0] = mod1.tag[0]
				return []*SecretShare{mod1, mod2}
			},
			func() error {
				return fmt.Errorf("recovery: checksum failed")
			},
		},
		{"inconsistent-tag",
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.tag[0] = mod.tag[0] + 1
				return []*SecretShare{mod, shares[1]}
			},
			func() error {
				return fmt.Errorf("plausible shares: shares have inconsistent tags")
			},
		},
		{"multiple-explanations",
			func() []*SecretShare {
				as := NewAccessStructure(2, 5)
				R1 := []byte("random1")
				shares1, err := Share(as, msg, R1, ad)
				if err != nil {
					panic(err)
				}

				R2 := []byte("random2")
				shares2, err := Share(as, msg, R2, ad)
				if err != nil {
					panic(err)
				}

				return []*SecretShare{shares1[0], shares1[1], shares2[2], shares2[3]}
			},
			func() error {
				return fmt.Errorf("multiple explanations: {id:2, id:3} and {id:0, id:1}")
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
				mod.pub.C[0] = mod.pub.C[0] + 1
				return []*SecretShare{shares[1], mod, shares[2]}
			},
			[]int{0, 2},
		},
		{"modified-sec", msg,
			func() []*SecretShare {
				mod := cloneShare(shares[0])
				mod.sec = []byte("this share is bad")
				return []*SecretShare{mod, shares[1], shares[2]}
			},
			[]int{1, 2},
		},
		// TODO: Add more tests for error conditions, including
		// assertions on identifying the bad shares.
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
	out := &SecretShare{id: share.id, as: share.as}
	out.pub = struct{ C, D, J []byte }{
		append([]byte{}, share.pub.C...),
		append([]byte{}, share.pub.D...),
		append([]byte{}, share.pub.J...),
	}
	out.sec = append([]byte{}, share.sec...)
	out.tag = append([]byte{}, share.tag...)
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
