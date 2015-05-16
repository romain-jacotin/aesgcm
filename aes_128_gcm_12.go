package main

import "crypto/aes"
import "crypto/cipher"
import "strings"
import "fmt"

type AesGcm struct {
	cipher cipher.Block
	h      []byte
	h0     uint64
	h1     uint64
}

func NewAesGcm(key *[]byte) *AesGcm {
	var err error
	var i uint

	a := new(AesGcm)
	a.h = make([]byte, 16)

	a.cipher, err = aes.NewCipher(*key)
	if err != nil {
		fmt.Printf("crypto.aes.NewCipher( []byte ) error\n")
		return nil
	}

	a.cipher.Encrypt(a.h, a.h)
	for i = 0; i < 8; i++ {
		a.h0 += uint64((a.h[i] << (i << 3)))
	}
	for i = 0; i < 8; i++ {
		a.h1 += uint64((a.h[i] << (i << 3)))
	}
	return a
}

func (this *AesGcm) EncryptThenMac(mac *[16]byte, cipher_text, associated_data, plain_text, nonce *[]byte) bool {

	// H = E(K,0^128)
	// Y0 = Nonce || 0^31 1      <-- if Nonce is 96 bits, otherwise Y0 = GHASH(H,{}, Nonce)
	//
	// for i = 1,...,n
	//   Yi = incr(Yi−1)
	// end for
	//
	// for i=1,...,n−1
	//   Ci = Pi xor E(K,Yi)
	// end for
	//
	// Cn =Pn xor MSB (E(K,Yn))
	//
	// T = MSBt( GHASH(H,A,C) xor E(K, Y0) )

	return true
}

func (this *AesGcm) AuthenticateThenDecrypt(mac *[16]byte, plain_text, associated_data, cipher_text, nonce *[]byte) bool {

	// H = E(K,0128)
	// Y0 = Nonce || i0^31 1      <-- if Nonce is 96 bits, otherwise Y0 = GHASH(H,{}, Nonce)
	//
	// T' = MSBt( GHASH(H,A,C) xor E(K,Y0) )
	//
	// for i = 1,...,n
	//   Yi = incr(Yi−1)
	// end for
	//
	// for i = 1,...,n-1
	//   Pi = Ci xor E(K,Yi)
	// end for
	//
	// Pn = Cn xor MSBu( E(K,Yn) )

	var tag [16]byte

	if len(*cipher_text) < len(*plain_text) {
		return false
	}

	this.ghash(&tag, associated_data, cipher_text)
	fmt.Printf("[GHASH]         = %x\n", tag)

	y0 := make([]byte, 16)
	for i := 0; i < 12; i++ {
		y0[i] = (*nonce)[i]
	}
	y0[15] = 1
	// fmt.Printf("[Y0]            = %x\n", y0)

	this.cipher.Encrypt(y0, y0)
	//fmt.Printf("[E(K,Y0)]       = %x\n", y0)

	for i := 0; i < 16; i++ {
		tag[i] ^= y0[i]
	}
	fmt.Printf("[GHASH^E(K,Y0)] = %x\n\n", tag)

	return true
}

func (this *AesGcm) ghash(tag *[16]byte, a, c *[]byte) {

	// GHASH(H, A, C) = Xm+n+1 where the variables Xi for i = 0,...,m+n+1 are defined as:
	//
	// STEP 1:
	// X0 = 0
	//
	// STEP 2:
	// for i = 1,...,m−1
	//   Xi = (Xi-1 xor Ai) * H
	// end for
	//
	// STEP 3:
	// Xm = (Xm-1 xor (Am || 0^(128−v)) * H
	//
	// STEP 4:
	// for i = m+1,...,m+n−1
	//   Xi = (Xi−1 xor Ci−m) * H
	// end for
	//
	// STEP 5:
	// Xm+n = (Xm+n-1 xor (Cn||0^(128−u)) * H
	//
	// STEP 6:
	// Xm+n+1 = (Xm+n xor (len(A) || len(C))) * H

	var x0, x1, a0, a1 uint64
	var i, j, k uint

	h0 := this.h0
	h1 := this.h1

	m := uint(len(*a))
	modm := m & 0xf
	v := uint64(m) << 3
	m >>= 4

	n := uint(len(*c))
	modn := n & 0xf
	u := uint64(n) << 3
	n >>= 4

	// STEP 1: Compute X0 = 0
	// --> x0 = x1 = 0 (default uint64 value)

	// STEP 2: Compute X1 to Xm-1
	for i = 0; i < m; i++ {
		// Compute Ai (= little endian uint128 in two uint64)
		a0 = 0
		a1 = 0
		for j = 0; j < 8; j++ {
			a0 += uint64((*a)[(i<<4)+j]) << (j << 3)
		}
		for j = 8; j < 16; j++ {
			a1 += uint64((*a)[(i<<4)+j]) << ((j - 8) << 3)
		}
		// Compute Xi = (Xi−1 xor Ai) * H
		x0, x1 = mult(x0^a0, x1^a1, h0, h1)
	}

	// STEP 3: Compute Xm = (Xm-1 xor (Am || 0^(128−v)) * H
	// Compute Am (= little endian uint128 in two uint64)
	if modm > 0 {
		a0 = 0
		a1 = 0
		if modm < 8 {
			k = modm
		} else {
			k = 8
		}
		for j = 0; j < k; j++ {
			a0 += uint64((*a)[(m<<4)+j]) << (j << 3)
		}
		if modm > 8 {
			k = modm
			for j = 8; j < k; j++ {
				a1 += uint64((*a)[(m<<4)+j]) << ((j - 8) << 3)
			}
		}
		// Compute Xm = (Xm-1 xor (Am || 0^(128−v)) * H
		x0, x1 = mult(x0^a0, x1^a1, h0, h1)
	}

	// STEP 4: Compute Xm+1 to Xm+n-1
	for i = 0; i < n; i++ {
		// Compute Ci (= little endian uint128 in two uint64)
		a0 = 0
		a1 = 0
		for j = 0; j < 8; j++ {
			a0 += uint64((*c)[(i<<4)+j]) << (j << 3)
		}
		for j = 8; j < 16; j++ {
			a1 += uint64((*c)[(i<<4)+j]) << ((j - 8) << 3)
		}

		// Compute Xi = (Xi−1 xor Ci−m) * H
		x0, x1 = mult(x0^a0, x1^a1, h0, h1)
	}

	// STEP 5: Compute Cn (= little endian uint128 in two uint64)
	if modn > 0 {
		a0 = 0
		a1 = 0
		if modn < 8 {
			k = modn
		} else {
			k = 8
		}
		for j = 0; j < k; j++ {
			a0 += uint64((*c)[(n<<4)+j]) << (j << 3)
		}
		if modn > 8 {
			k = modn
			for j = 8; j < k; j++ {
				a1 += uint64((*c)[(n<<4)+j]) << ((j - 8) << 3)
			}
		}
		// Compute Xm+n = (Xm+n-1 xor (Cn||0^(128−u)) * H
		x0, x1 = mult(x0^a0, x1^a1, h0, h1)
	}

	// STEP 6: Xm+n+1 = (Xm+n xor (len(A) || len(C))) * H
	// Compute len(a) || len(b)
	a0 = u | v
	a1 = 0 // normally the AAD and Plain text are far less than 2^64 bits ...

	// Compute Xm+n+1 = (Xm+n xor (len(A) || len(C))) * H
	x0, x1 = mult(x0^a0, x1^a1, h0, h1)

	// Write GHASH as Little Endian
	for i = 0; i < 8; i++ {
		tag[i] = byte((x0 >> (i << 3)) & 0xff)
	}
	for i = 0; i < 8; i++ {
		tag[i+8] = byte((x1 >> (i << 3)) & 0xff)
	}
}

func mult(x0, x1, y0, y1 uint64) (z0, z1 uint64) {

	// Multiplication in Galois Field (2^128): Computes the value of Z = X * Y, where X,Y and Z are one of GF(2^128).
	//
	// Z = 0
	// V = X
	//
	// for i = 0 to 127 do
	//
	//   if Yi = 1 then Z = Z xor V
	//   end if
	//
	//   if V127 = 0 then
	//     V = rightshift( V )
	//   else
	//     V = rightshift( V ) xor R
	//   end if
	//
	// end for

	var i uint
	// z0 = z1 = 0 (default uint64 value)

	v0 := x0
	v1 := x1
	for i = 0; i < 64; i++ {
		//   if Yi = 1 then Z = Z xor V
		if (y0 & (1 << i)) > 0 {
			z0 ^= v0
			z1 ^= v1
		}
		// V = rightshift( V )
		v0 = v0>>1 | ((v1 & 1) << 63)
		v1 >>= 1
		//   if V127 = 1 then V = V xor R
		if (v1 & 0x8000000000000000) > 0 {
			z0 ^= v0
			z1 ^= v1
		}
	}
	for i = 0; i < 64; i++ {
		//   if Yi = 1 then Z = Z xor V
		if (y1 & (1 << i)) > 0 {
			z0 ^= v0
			z1 ^= v1
		}
		// V = rightshift( V )
		v0 = v0>>1 | ((v1 & 1) << 63)
		v1 >>= 1
		//   if V127 = 1 then V = V xor R
		if (v1 & 0x8000000000000000) > 0 {
			z0 ^= v0
			z1 ^= v1
		}
	}
	return
}

func main() {
	fmt.Printf("\n")

	testDecrypt_AES_GCM_12(
		toByte("cf063a34d4a9a76c2c86787d3f96db71"),
		toByte("113b9785971864c83b01c787"),
		&[]byte{},
		&[]byte{},
		toByte("72ac8493e3a5228b5d130a69d2510e42"),
		&[]byte{})

	testDecrypt_AES_GCM_12(
		toByte("a49a5e26a2f8cb63d05546c2a62f5343"),
		toByte("907763b19b9b4ab6bd4f0281"),
		&[]byte{},
		&[]byte{},
		toByte("a2be08210d8c470a8df6e8fbd79ec5cf"),
		&[]byte{})

	testDecrypt_AES_GCM_12(
		toByte("d1f6af919cde85661208bdce0c27cb22"),
		toByte("898c6929b435017bf031c3c5"),
		&[]byte{},
		toByte("7c5faa40e636bbc91107e68010c92b9f"),
		toByte("ae45f11777540a2caeb128be8092468a"),
		&[]byte{})

	testDecrypt_AES_GCM_12(
		toByte("2370e320d4344208e0ff5683f243b213"),
		toByte("04dbb82f044d30831c441228"),
		&[]byte{},
		toByte("d43a8e5089eea0d026c03a85178b27da"),
		toByte("2a049c049d25aa95969b451d93c31c6e"),
		&[]byte{})

	testDecrypt_AES_GCM_12(
		toByte("e98b72a9881a84ca6b76e0f43e68647a"),
		toByte("8b23299fde174053f3d652ba"),
		toByte("5a3c1cf1985dbb8bed818036fdd5ab42"),
		&[]byte{},
		toByte("23c7ab0f952b7091cd324835043b5eb5"),
		toByte("28286a321293253c3e0aa2704a278032"))

	testDecrypt_AES_GCM_12(
		toByte("33240636cd3236165f1a553b773e728e"),
		toByte("17c4d61493ecdc8f31700b12"),
		toByte("47bb7e23f7bdfe05a8091ac90e4f8b2e"),
		&[]byte{},
		toByte("b723c70e931d9785f40fd4ab1d612dc9"),
		toByte("95695a5b12f2870b9cc5fdc8f218a97d"))

	testDecrypt_AES_GCM_12(
		toByte("5164df856f1e9cac04a79b808dc5be39"),
		toByte("e76925d5355e0584ce871b2b"),
		toByte("0216c899c88d6e32c958c7e553daa5bc"),
		&[]byte{},
		toByte("a145319896329c96df291f64efbe0e3a"),
		&[]byte{})
}

func toByte(s string) *[]byte {
	bs := []byte(strings.ToLower(s))
	b := make([]byte, len(bs)/2)

	for i := 0; i < len(s)/2; i++ {
		switch bs[i*2] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			b[i] = (bs[i*2] - '0') << 4
		case 'a', 'b', 'c', 'd', 'e', 'f':
			b[i] = (bs[i*2] - 'a' + 10) << 4
		}
		switch bs[i*2+1] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			b[i] += (bs[i*2+1] - '0')
		case 'a', 'b', 'c', 'd', 'e', 'f':
			b[i] += (bs[i*2+1] - 'a' + 10)
		}
	}
	return &b
}

func testDecrypt_AES_GCM_12(key, nonce, aad, ciphertext, tag, waitingplain *[]byte) {
	var t [16]byte
	pt := make([]byte, len(*ciphertext))
	aead := NewAesGcm(key)

	for i := 0; i < 16; i++ {
		t[i] = (*tag)[i]
	}
	fmt.Printf("DECRYPTION TEST:\n----------------\n")
	fmt.Printf("Key             : [16] %x\n", *key)
	fmt.Printf("Nonce           : [12] %x\n", *nonce)
	fmt.Printf("Associated data : [%d] %x\n", len(*aad), *aad)
	fmt.Printf("Cipher text     : [%d] %x\n", len(*ciphertext), *ciphertext)
	fmt.Printf("Tag             : [%d] %x\n\n", len(*tag), *tag)
	fmt.Printf("Authenticate    :      %v\n", aead.AuthenticateThenDecrypt(&t, &pt, aad, ciphertext, nonce))
	fmt.Printf("Plain text      : [%d] %x\n", len(pt), pt)
	fmt.Printf("Waiting Plain --> [%d] %x\n", len(*waitingplain), *waitingplain)
	fmt.Printf("----------------\n\n")
}

func testEncrypt_AES_GCM_12(aad, plaintext, key, nonce *[]byte, waitingcipher string, waitingval string) {
	var tag [16]byte
	ct := make([]byte, len(*plaintext))
	aead := NewAesGcm(key)

	aead.EncryptThenMac(&tag, &ct, aad, plaintext, nonce)
	fmt.Printf("ENCRYPTION TEST:\n----------------\n")
	fmt.Printf("Key             : [16] %x\n", *key)
	fmt.Printf("Nonce           : [12] %x\n", *nonce)
	fmt.Printf("Associated data : [%d] %x\n", len(*aad), *aad)
	fmt.Printf("Plain text      : [%d] %x\n\n", len(*plaintext), *plaintext)
	fmt.Printf("Cipher text     : [%d] %x\n", len(ct), ct)
	fmt.Printf("Waiting cipher--> [%d] %s\n", len(waitingcipher), waitingcipher)
	fmt.Printf("Tag             : [%d] %x\n", len(tag), tag)
	fmt.Printf("Waiting tag-----> [%d] %s\n", len(waitingval), waitingval)
	fmt.Printf("----------------\n\n")
}
