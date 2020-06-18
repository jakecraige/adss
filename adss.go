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
	return exAxRecover(shares)
}

// exAxRecover implements the EX transform (figure 9) on top of the AX transform
func exAxRecover(shares []*SecretShare) ([]byte, error) {
	allShareSets, err := computeKPlausibleShareSets(shares)
	if err != nil {
		return nil, err
	}

	// Find the first explanation of these shares
	var firstExplanationIdx int
	var M []byte
	for i, shares := range allShareSets {
		M, err = axRecover(shares)

		// NOTE: On line 81 in figure 9, we are told to verify that V = S_i, or that
		// the recovered shares match the input shares. This is in fact already done
		// within axRecover as described in figure 8 line 31B so we do not duplicate
		// that here. The fact that axRecover does not error is sufficient to cover
		// this check.
		// TODO: Verify the above statement is accurate. I found this section
		// a little difficult to understand how all the sets were interacting.
		if err == nil {
			// We have found our explanation so we break out of the loop.
			firstExplanationIdx = i
			break
		}
	}

  // TODO: Need to identify which are the bad shares and identify them to the caller

	// We now seek a second explanation of these shares that is different from the first.
	// If we find one, there is an issue with the shares and we fail.
	for _, shares := range allShareSets {
    // Skip share sets that are subsets of the first valid one
		if isSubset(shares, allShareSets[firstExplanationIdx]) {
      continue
    }

		// TODO: Similar to the note about, we check the equivalence of the
		// recovered message since validator of the shares is done within axRecover.
		// We need to confirm this is acceptable.
		Mprime, err := axRecover(shares)
		if err != nil {
			continue
		}
		if !bytes.Equal(M, Mprime) {
			return nil, fmt.Errorf("invalid shares found")
		}
	}

	return M, nil
}


func isSubset(subset, set []*SecretShare) bool {
  if len(subset) > len(set) {
    return false
  }

  for _, subsetItem := range subset {
    found := false
    for _, setItem := range set {
      if subsetItem == setItem {
        found = true
        break
      }
    }

    if !found { // if we cannot find one item, it is not a subset
      return false
    }
  }

  return true
}

func computeKPlausibleShareSets(shares []*SecretShare) ([][]*SecretShare, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	// First we validate consistency of the shares:
	//   they have unique indexes, the same access structure, and tags
	//   We don't check that the indexes are valid for the access structure as
	//   this is done in axRecover already.
	as, tag := shares[0].as, shares[0].tag
	seenIndexes := map[uint8]bool{shares[0].id: true}
	for _, share := range shares[1:] {
		if share.as != as {
			return nil, fmt.Errorf("shares have inconsistent access structure")
		}

		if !bytes.Equal(share.tag, tag) {
			return nil, fmt.Errorf("shares have inconsistent tags")
		}

		if seenIndexes[share.id] {
			return nil, fmt.Errorf("duplicate share id found")
		}
		seenIndexes[share.id] = true
	}

  // We compute all subsets of different sizes above the threshold to use for recovery.
  // TODO: Need to confirm the expected ordering of these subsets and their
  // interaction with skipping subsets of them in the error correcting logic.
  out := make([][]*SecretShare, 0)
  for i := int(as.t); i <= len(shares); i++ {
    out = append(out, kSubsets(i, shares)...)
  }
	return out, nil
}

func kSubsets(k int, shares []*SecretShare) [][]*SecretShare {
	if k > len(shares) {
		panic(fmt.Sprintf("not enough shares to create subsets, k: %d, len: %d", k, len(shares)))
	}

	// If k is equal to the length, there are no subsets so we just return them.
	if k == len(shares) {
		return [][]*SecretShare{shares}
	}

	out := make([][]*SecretShare, 0)

	// Triple nested for loops with index manipluation are always a bit complex to
	// understand but I'll try to explain what this is doing here.
	//
	// It uses a psuedo-windowing strategy where we start at the first index and
	// then try to find the next k-1 elements going forward in the list. We use
	// k-1 because we always include the i-th element in the start of the set.
	//
	// By only going forward we are able to prevent creating any subsets which are
	// permutations of existing ones.
	for i := 0; i < len(shares); i++ {
		for j := i + 1; j < len(shares); j++ {
			// If this value is larger than the number of shares, we won't be able to
			// find a total k shares for our subset, so we bail out.
			if j+k-1 > len(shares) {
				break
			}

			set := []*SecretShare{shares[i]}
			for l := 0; l < k-1; l++ {
				set = append(set, shares[j+l])
			}

			out = append(out, set)
		}
	}

	return out
}

// axRecover implements the AX transform (figure 8) over the the base secret sharing scheme
func axRecover(shares []*SecretShare) ([]byte, error) {
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
