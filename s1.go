package adss

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

type s1SecretShare struct {
	i, t, n uint8
	secret  []byte
}

func s1Share(A AccessStructure, M, R, T []byte) ([]*s1SecretShare, error) {
	// Use HKDF-SHA256 as our PRF, keying it with the provided randomness
	prf := hkdf.New(sha256.New, R, nil, T)

	secrets := make([][]byte, A.n)
	for i := range secrets {
		secrets[i] = make([]byte, len(M))
	}

	for i, msgBlock := range M { // for each message block
		poly, err := makePolynomial(msgBlock, A.t-1, prf)
		if err != nil {
			return nil, err
		}

		for j := 0; j < int(A.n); j++ { // create shares for each party
			// We use j+1 here since we don't want to evaluate at 0, as that's the secret :)
			secrets[j][i] = poly.evaluate(uint8(j + 1))
		}
	}

	shares := make([]*s1SecretShare, A.n)
	for i, secret := range secrets {
		shares[i] = &s1SecretShare{
			i:      uint8(i),
			t:      A.t,
			n:      A.n,
			secret: secret,
		}
	}

	return shares, nil
}

func s1Recover(shares []*s1SecretShare) ([]byte, error) {
	if shares == nil || len(shares) < 1 {
		return nil, fmt.Errorf("missing argument: shares, was nil or 0 length")
	}

	t := len(shares)
	k, mLen := shares[0].t, len(shares[0].secret)
	if t < int(k) {
		return nil, fmt.Errorf("not enough shares provided, got: %d, need: %d", t, k)
	}

	msg := make([]byte, mLen)
	for i := range msg {
		xSamples := make([]uint8, t)
		ySamples := make([]uint8, t)

		for j, share := range shares {
			xSamples[j] = share.i + 1 // +1 to account for how we evaluated it in sharing
			ySamples[j] = share.secret[i]
		}

		msg[i] = interpolatePolynomial(xSamples, ySamples, 0)
	}

	return msg, nil
}
