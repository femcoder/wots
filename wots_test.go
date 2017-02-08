package wots

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSetParams(t *testing.T) {
	// Test
	params, _ := SetParams(32, 4)

	if params.length1 != 128 {
		t.Errorf("length1 not computed correctly.")
	}

	if params.length2 != 7 {
		t.Errorf("length2 not computed correctly.")
	}

	params, err := SetParams(16, 4)
	if err == nil {
		t.Errorf("Invalid parameters allowed.")
	}

	params, err = SetParams(32, 7)
	if err == nil {
		t.Errorf("Invalid parameters allowed.")
	}
}

func TestKeyGen(t *testing.T) {
	params, _ := SetParams(32, 4)
	masterkey := make([]byte, 32)

	for i := 0; i < 32; i++ {
		masterkey[i] = byte(i)
	}

	sk, pk := KeyGen(masterkey, params)

	if len(sk) != len(pk) {
		t.Errorf("Public key and private key length do not match.")
	}
}

func TestSignVerify(t *testing.T) {
	params, _ := SetParams(32, 4)
	masterkey1 := make([]byte, 32)
	masterkey2 := make([]byte, 32)
	message1 := make([]byte, 32)

	// Random key and messages
	rand.Read(masterkey1)
	rand.Read(masterkey2)
	rand.Read(message1)

	sk1, pk1 := KeyGen(masterkey1, params)
	_, pk2 := KeyGen(masterkey2, params)

	signature1 := Sign(message1, sk1, params)

	if !Verify(message1, pk1, signature1, params) {
		t.Error("Signature not valid.")
	}

	signature2 := Sign(message1, sk1, params)

	if !bytes.Equal(signature1, signature2) {
		t.Errorf("Signing is not deterministic.")
	}

	if Verify(message1, pk2, signature1, params) {
		t.Errorf("Signature verified with wrong key.")
	}
}

func TestSignVerifyLarge(t *testing.T) {
	params, _ := SetParams(64, 16)
	masterkey1 := make([]byte, 64)
	masterkey2 := make([]byte, 64)
	message1 := make([]byte, 64)

	// Random key and messages
	rand.Read(masterkey1)
	rand.Read(masterkey2)
	rand.Read(message1)

	sk1, pk1 := KeyGen(masterkey1, params)
	_, pk2 := KeyGen(masterkey2, params)

	signature1 := Sign(message1, sk1, params)

	if !Verify(message1, pk1, signature1, params) {
		t.Error("Signature not valid.")
	}

	signature2 := Sign(message1, sk1, params)

	if !bytes.Equal(signature1, signature2) {
		t.Errorf("Signing is not deterministic.")
	}

	if Verify(message1, pk2, signature1, params) {
		t.Errorf("Signature verified with wrong key.")
	}

}
