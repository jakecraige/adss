package adss

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
)

type AccessStructure struct {
	t, n uint8
}

func NewAccessStructure(t, n uint8) AccessStructure {
	return AccessStructure{t: t, n: n}
}

func (as *AccessStructure) Bytes() []byte {
	bytes := make([]byte, 2)
	bytes[0] = as.t
	bytes[1] = as.n
	return bytes
}

func (as *AccessStructure) isValidIndex(idx uint8) bool {
	return idx >= 0 && idx < as.n
}

type SecretShare struct {
	as  AccessStructure // S.as
	id  uint8           // S.id
	pub struct {        // S.pub
		C, D, J []byte
	}
	sec []byte // S.sec
	tag []byte // S.tag
}

func (ss *SecretShare) Equal(other *SecretShare) bool {
	return bytes.Equal(ss.Bytes(), other.Bytes())
}

func (ss *SecretShare) Bytes() []byte {
	out := make([]byte, 0)
  // TODO: This is currently an unrecoverable byte encoding since we have
  // variable length message and associated data. We'll need to update this to
  // be decodable later for serialization to disk purpoes.
	out = append(out, ss.as.Bytes()...)
	out = append(out, ss.id)
	out = append(out, ss.pub.C...)
	out = append(out, ss.pub.D...)
	out = append(out, ss.pub.J...)
	out = append(out, ss.sec...)
	out = append(out, ss.tag...)
	return out
}

// Share creates an ADSS secret sharing of the provided message and returns the shares or error.
//
// A: the acccess structure to split the message with
// M: message
// R: random coins, might not be uniform
// T: associated data authenticated during sharing
func Share(A AccessStructure, M, R, T []byte) ([]*SecretShare, error) {
	// 1. Hash the inputs to get J K L
	J, K, L := computeJKL(A, M, R, T)

	// 2. Encrypt the message and the randomness into C and D
	C, D, err := xorKeyStreamTwoInputs(K[:], M, R)
	if err != nil {
		return nil, err
	}

	// 3. Split the key into secret shares
	shares := make([]*SecretShare, A.n)
	// TODO: What is the epsilon that is provided here in the paper?
	s1Shares, err := s1Share(A, K, L, nil)
	if err != nil {
		return nil, err
	}

	// 4. Construct final secret shares and return them
	for i := range shares {
		shares[i] = &SecretShare{
			as:  A,
			id:  s1Shares[i].i,
			pub: struct{ C, D, J []byte }{C, D, J},
			sec: s1Shares[i].secret,
			tag: T,
		}
	}

	return shares, nil
}

func Recover(shares []*SecretShare) ([]byte, error) {
	s1Shares := make([]*s1SecretShare, len(shares))
	for i, share := range shares {
		s1Shares[i] = &s1SecretShare{
			i:      share.id,
			t:      share.as.t,
			n:      share.as.n,
			secret: share.sec,
		}
	}

	K, err := s1Recover(s1Shares)
	if err != nil {
		return nil, err
	}

	share0 := shares[0]
	A, C, D, J, T := share0.as, share0.pub.C, share0.pub.D, share0.pub.J, share0.tag

	M, R, err := xorKeyStreamTwoInputs(K, C, D)
	if err != nil {
		return nil, err
	}

	// Verify the integrity of the recovered params
	// TODO: The paper mentions verifying the L value too, but we don't have it in
	// the share output. Where does it come from? Is it supposed to be in the share.pub?
	recovJ, recovK, _ := computeJKL(A, M, R, T)
	if !bytes.Equal(recovJ, J) || !bytes.Equal(recovK, K) {
		return nil, fmt.Errorf("invalid shares")
	}

	reshares, err := Share(A, M, R, T)
	if err != nil {
		panic(err)
	}

	for _, share := range shares {
		// verify the id is valid
		if !A.isValidIndex(share.id) {
			return nil, fmt.Errorf("invalid share, invalid index: %d", share.id)
		}

		// verify the share is one of the known shares when we recompute them
		// from recovered data.
		match := false
		for _, reshare := range reshares {
			if reshare.Equal(share) {
				match = true
				break
			}
		}
		if !match {
			return nil, fmt.Errorf("invalid share, no match found in resharing")
		}
	}

	return M, nil
}

// xorKeyStreamTwoInputs will derive an AES keystream using the key and then
// generate a unique keystream for each input using the IV as a domain separator
// and return the output. This can be used to encrypt and decrypt.
func xorKeyStreamTwoInputs(k, p1, p2 []byte) ([]byte, []byte, error) {
	ciph, err := aes.NewCipher(k)
	if err != nil {
		return nil, nil, err
	}

	stream1 := cipher.NewCTR(ciph, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	c1 := make([]byte, len(p1))
	stream1.XORKeyStream(c1, p1)

	stream2 := cipher.NewCTR(ciph, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	c2 := make([]byte, len(p2))
	stream2.XORKeyStream(c2, p2)

	return c1, c2, nil
}

func computeJKL(A AccessStructure, M, R, T []byte) ([]byte, []byte, []byte) {
	aBytes := A.Bytes()
	input := make([]byte, len(aBytes)+len(M)+len(R)+len(T))
	copy(input, aBytes)
	copy(input[len(aBytes):], M)
	copy(input[len(aBytes)+len(M):], R)
	copy(input[len(aBytes)+len(M)+len(R):], T)

	// Incrementing integers used for domain separation because we use the same input
	J1 := sha256.Sum256(append([]byte{1}, input...))
	J2 := sha256.Sum256(append([]byte{2}, input...))
	J := append(J1[:], J2[:]...)
	K := sha256.Sum256(append([]byte{3}, input...))
	L := sha256.Sum256(append([]byte{4}, input...))

	return J[:], K[:], L[:]
}
