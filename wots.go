/*
Package wots implements the Winternitz One-time Signature (WOTS) Scheme.

There are two parameters:

-n which determines the security level (given in bytes)
-w which allows a trade-off between signature size and computation costs.

The implementation only allows n = {32, 64} at the moment and uses SHA256
resp. SHA512 to provide a (classical) security level of 256-bit resp. 512-bit.

A secret key MUST only be used to sign ONE message.
*/
package wots

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math"
)

// Wotsparams holds all parameters needed for computing signatures with WOTS.
type Wotsparams struct {
	length1 int
	length2 int
	length  int
	n       int
	w       int
	logw    int
	keysize int
}

// SetParams takes the security parameter n and the winternitz parameter
// w to initialize all parameters for the WOTS.
func SetParams(n int, w int) (params Wotsparams, err error) {
	if (w & (w - 1)) != 0 {
		return params, errors.New("w has to be a power of 2")
	}

	if n != 32 && n != 64 {
		return params, errors.New("n has to be 32 or 64")
	}

	params.n = n
	params.w = w
	params.logw = int(math.Log2(float64(w)))
	params.length1 = int(math.Ceil(float64((8 * n) / params.logw)))
	params.length2 = int(math.Floor(math.Log2(float64(params.length1*(w-1)/
		params.logw) + 1)))
	params.length = params.length1 + params.length2
	return params, nil
}

// KeyGen generates the secret key (sk) / public key (pk) pair for WOTS from a
// master key. The master key MUST be chosen uniformly at random.
func KeyGen(masterkey []byte, params Wotsparams) (sk []byte, pk []byte) {
	sk = expandKey(masterkey, params)
	pk = make([]byte, params.n*params.length)

	for i := 0; i < params.length; i++ {
		tmpChain := genChain(sk[i*params.n:(i+1)*params.n], 0, params.w-1, params)
		copy(pk[i*params.n:], tmpChain)
	}

	return sk, pk
}

// Sign computes the signature for message using the secret key sk.
func Sign(message []byte, sk []byte, params Wotsparams) (signature []byte) {
	messageDigest := corehash(message, params.n)
	b := computeB(messageDigest, params)
	// Compute Signature
	signature = make([]byte, params.n*params.length)

	for i := 0; i < params.length; i++ {
		tmpChain := genChain(sk[i*params.n:(i+1)*params.n], 0, b[i], params)
		copy(signature[i*params.n:], tmpChain)
	}
	return signature
}

// Verify returns true if signature is a valid signature for message using pk.
func Verify(message []byte, pk []byte, signature []byte, params Wotsparams) bool {
	messageDigest := corehash(message, params.n)
	b := computeB(messageDigest, params)

	for i := 0; i < params.length; i++ {
		tmpChain := genChain(signature[i*params.n:(i+1)*params.n], 0, params.w-1-b[i], params)
		// Verify with pk
		if !bytes.Equal(pk[params.n*i:params.n*(i+1)], tmpChain) {
			return false
		}
	}

	return true
}

func computeB(message []byte, params Wotsparams) (b []int) {
	// Convert message to base_w
	messageBasew := baseW(message, params)

	// Compute checksum
	checksum := 0
	for _, m := range messageBasew {
		checksum += params.w - 1 - m
	}

	// Convert checksum to base_w
	buffer := make([]byte, 8)
	checksumBytes := make([]byte, params.length2)
	binary.LittleEndian.PutUint64(buffer, uint64(checksum))
	copy(checksumBytes, buffer)
	checksumBasew := baseW(checksumBytes, params)

	b = append(messageBasew, checksumBasew...)
	return b
}

// BaseW converts a byte array to a base w representation of its content.
func baseW(input []byte, params Wotsparams) []int {
	var in, out, tmp, bits int

	output := make([]int, 8*len(input)/params.logw)

	bits = 0

	for consumed := 0; consumed < 8*len(input)/params.logw; consumed++ {
		if bits == 0 {
			tmp = int(input[in])
			in++
			bits += 8
		}
		bits -= params.logw
		output[out] = (tmp >> uint(bits)) & (params.w - 1)
		out++
	}
	return output
}

// expandKey expands an n-byte key to a len * n byte array
func expandKey(key []byte, params Wotsparams) (outseeds []byte) {
	var buffer []byte
	for i := 0; i < params.length; i++ {
		counter := make([]byte, params.n)
		for j := 0; j < params.n; j++ {
			counter = append(counter, byte(i))
		}
		buffer = append(buffer, prf(counter, key, params.n)...)
	}
	return buffer
}

func genChain(in []byte, start int, steps int, params Wotsparams) []byte {
	out := make([]byte, params.n)

	copy(out, in)

	for i := 0; i < (start+steps) && i < params.w; i++ {
		out = hashf(out, params.n)
	}
	return out
}

func hashf(in []byte, n int) (out []byte) {
	var buffer []byte

	buffer = append(buffer, in...)

	return corehash(buffer, n)
}

// prf is a pseudo-random function, which takes a key and an n-byte input
// to produce an n-byte output.
func prf(in []byte, key []byte, n int) (out []byte) {
	var buffer []byte

	buffer = append(buffer, key...)
	buffer = append(buffer, in...)

	return corehash(buffer, n)
}

func corehash(in []byte, n int) []byte {
	switch n {
	case 32:
		checksum := sha256.Sum256(in)
		return checksum[:]
	case 64:
		checksum := sha512.Sum512(in)
		return checksum[:]
	default:
		checksum := sha256.Sum256(in)
		return checksum[:]
	}
}
