// Package 'aesgcm' provides authenticated encryption with associated data primitives (AEAD)
// for AES GCM algorithms (Advanced Encryption Standard with Galois Counter Mode)
// as described in RFC5119 and RFC5258
//
// https://tools.ietf.org/html/rfc5116
//
// https://tools.ietf.org/html/rfc5282
package aesgcm

import "crypto/aes"
import "crypto/cipher"
import "errors"

type AEAD interface {
	// EncryptThenMac encrypts the plain_text in cipher_text slice, and authenticates associateddata and cipher_text in tag slice
	// The nonce anf tag size must match the sizes corresponding with the choosen AEAD algorithm.
	// cipher_text and plain_text must have equal size.
	EncryptThenMac(tag, cipher_text, associateddata, plain_text, nonce []byte) bool

	// AuthenticateThenDecrypt authenticates associateddata and cipher_text by checking the tag and, if successful, decrypt the cipher_text in plain_text
	// The nonce anf tag size must match the sizes corresponding with the choosen AEAD algorithm.
	// plain_text and cipher_text must have equal size.
	AuthenticateThenDecrypt(tag, plain_text, associateddata, cipher_text, nonce []byte) bool
}

type internalAEAD struct {
	ag        AEAD
	nonceSize int
	tagSize   int
}

type aesGcm struct {
	cipher cipher.Block
	y      [16]byte
	n      [16]byte
	h0     uint64
	h1     uint64
}

func (this *internalAEAD) EncryptThenMac(tag, cipher_text, associated_data, plain_text, nonce []byte) bool {
	if len(nonce) != this.nonceSize {
		return false
	}
	if len(tag) != this.tagSize {
		return false
	}
	return this.ag.EncryptThenMac(tag, cipher_text, associated_data, plain_text, nonce)
}

func (this *internalAEAD) AuthenticateThenDecrypt(tag, plain_text, associated_data, cipher_text, nonce []byte) bool {
	if len(nonce) != this.nonceSize {
		return false
	}
	if len(tag) != this.tagSize {
		return false
	}
	return this.ag.AuthenticateThenDecrypt(tag, plain_text, associated_data, cipher_text, nonce)
}

// NewAES_128_GCM returns an AEAD with the AEAD_AES_128_GCM algorithm's properties (as described in RFC5116).
//
// Notes: if key's length is not 16 bytes an error is return, nil otherwise
func NewAES_128_GCM(key []byte) (AEAD, error) {
	if len(key) != 16 {
		return nil, errors.New("aead: AES_128_GCM requires 128-bit key")
	}
	a := new(internalAEAD)
	a.ag = NewAesGcm(key)
	a.nonceSize = 12
	a.tagSize = 16
	return a, nil
}

// NewAES_256_GCM returns an AEAD with the AEAD_AES_256_GCM algorithm's properties (as described in RFC5116).
//
// Notes: if key's length is not 32 bytes an error is return, nil otherwise
func NewAES_256_GCM(key []byte) (AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("aead: AES_256_GCM requires 256-bit key")
	}
	a := new(internalAEAD)
	a.ag = NewAesGcm(key)
	a.nonceSize = 12
	a.tagSize = 16
	return a, nil
}

// NewAES_128_GCM_8 returns an AEAD with the AEAD_AES_128_GCM_8 algorithm's properties (as described in RFC5282).
//
// Notes: if key's length is not 16 bytes an error is return, nil otherwise
func NewAES_128_GCM_8(key []byte) (AEAD, error) {
	if len(key) != 16 {
		return nil, errors.New("aead: AES_128_GCM_8 requires 128-bit key")
	}
	a := new(internalAEAD)
	a.ag = NewAesGcm(key)
	a.nonceSize = 12
	a.tagSize = 8
	return a, nil
}

// NewAES_256_GCM_8 returns an AEAD with the AEAD_AES_256_GCM_8 algorithm's properties (as described in RFC5282).
//
// Notes: if key's length is not 32 bytes an error is return, nil otherwise
func NewAES_256_GCM_8(key []byte) (AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("aead: AES_256_GCM_8 requires 256-bit key")
	}
	a := new(internalAEAD)
	a.ag = NewAesGcm(key)
	a.nonceSize = 12
	a.tagSize = 8
	return a, nil
}

// NewAES_128_GCM_12 returns an AEAD with the AEAD_AES_128_GCM_12 algorithm's properties (as described in RFC5282).
//
// Notes: if key's length is not 16 bytes an error is return, nil otherwise
func NewAES_128_GCM_12(key []byte) (AEAD, error) {
	if len(key) != 16 {
		return nil, errors.New("aead: AES_128_GCM_12 requires 128-bit key")
	}
	a := new(internalAEAD)
	a.ag = NewAesGcm(key)
	a.nonceSize = 12
	a.tagSize = 12
	return a, nil
}

// NewAES_256_GCM_12 returns an AEAD with the AEAD_AES_256_GCM_12 algorithm's properties (as described in RFC5282).
//
// Notes: if key's length is not 32 bytes an error is return, nil otherwise
func NewAES_256_GCM_12(key []byte) (AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("aead: AES_256_GCM_12 requires 256-bit key")
	}
	a := new(internalAEAD)
	a.ag = NewAesGcm(key)
	a.nonceSize = 12
	a.tagSize = 12
	return a, nil
}

// NewAesGcm returns an AEAD with associated AES GCM algorithm properties.
// If key's length is 16 bytes then AES 128-bit is used as a cipher suite
// If key's length is 24 bytes then AES 192-bit is used as a cipher suite
// If key's length is 32 bytes then AES 256-bit is used as a cipher suite
//
// Notes: if key's length is not 16, 24 or 32 bytes an error is return, nil otherwise
func NewAesGcm(key []byte) AEAD {
	var err error
	var i uint32
	var h [16]byte

	a := new(aesGcm)

	a.cipher, err = aes.NewCipher(key)
	if err != nil {
		return nil
	}

	a.cipher.Encrypt(h[:], a.y[:])
	for i = 0; i < 8; i++ {
		a.h1 += uint64(h[i]) << (56 - (i << 3))
	}
	for i = 0; i < 8; i++ {
		a.h0 += uint64(h[i+8]) << (56 - (i << 3))
	}
	return a
}

func (this *aesGcm) EncryptThenMac(tag, cipher_text, associated_data, plain_text, nonce []byte) bool {

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
	// Cn =Pn xor MSBv(E(K,Yn))
	//
	// T = MSBt( GHASH(H,A,C) xor E(K, Y0) )

	var c, i, j, n, modn uint32
	var y0_12, y0_13, y0_14, y0_15 byte

	if len(cipher_text) < len(plain_text) {
		return false
	}

	// Compute Nonce prefix
	//   * For a fix value of the key, each Nonce must be distinct, but need not have equal lengths.
	//   * 96-bit nonce values can be processed more efficiently, so that length is recommended for situations in which efficiency is critical.
	//   * If an IV with a length other than 96 bits is used with a particular key, then that key must be used with a tag length of 128.
	//   * The nonce is authenticated, and it is not necessary to include it in the AAD field.
	if len(nonce) == 12 {
		for i = 0; i < 12; i++ {
			this.n[i] = nonce[i]
			y0_12 = 0
			y0_13 = 0
			y0_14 = 0
			y0_15 = 1
		}
		c = 1
	} else {
		this.ghash(tag, nil, nonce)
		for i = 0; i < 16; i++ {
			this.n[i] = tag[i]
		}
		y0_12 = this.n[12]
		y0_13 = this.n[13]
		y0_14 = this.n[14]
		y0_15 = this.n[15]
		c = (uint32(y0_12) << 24) | (uint32(y0_13) << 16) | (uint32(y0_14) << 8) | uint32(y0_15)
	}

	// Encryption of the plain text
	n = uint32(len(plain_text))
	modn = n & 0xf
	n >>= 4
	for i = 0; i < n; i++ {
		// Compute Yi = incr(Yi−1)
		c++
		this.n[15] = byte(c & 0xff)
		this.n[14] = byte((c >> 8) & 0xff)
		this.n[13] = byte((c >> 16) & 0xff)
		this.n[12] = byte((c >> 24) & 0xff)
		// Compute E(K,Yi)
		this.cipher.Encrypt(this.y[:], this.n[:])
		// Compute Ci = Pi xor E(K,Yi)
		for j = 0; j < 16; j++ {
			cipher_text[(i<<4)+j] = plain_text[(i<<4)+j] ^ this.y[j]
		}
	}
	if modn > 0 {
		// Compute Yn = incr(Yn−1)
		c++
		this.n[15] = byte(c & 0xff)
		this.n[14] = byte((c >> 8) & 0xff)
		this.n[13] = byte((c >> 16) & 0xff)
		this.n[12] = byte((c >> 24) & 0xff)
		// Compute E(K,Yn)
		this.cipher.Encrypt(this.y[:], this.n[:])
		// Compute Cn = Pn xor MSBv( E(K,Yn) )
		for j = 0; j < modn; j++ {
			cipher_text[(n<<4)+j] = plain_text[(n<<4)+j] ^ this.y[j]
		}
	}

	this.ghash(tag, associated_data, cipher_text)
	// Compute Y0
	this.n[12] = y0_12
	this.n[13] = y0_13
	this.n[14] = y0_14
	this.n[15] = y0_15
	// Compute E(K,Y0)
	this.cipher.Encrypt(this.y[:], this.n[:])
	// Compute GHASH^E(K,Y0)
	for i = 0; i < 16; i++ {
		tag[i] ^= this.y[i]
	}
	return true
}

func (this *aesGcm) AuthenticateThenDecrypt(tag, plain_text, associated_data, cipher_text, nonce []byte) bool {

	// H = E(K,0^128)
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

	var c, i, j, n, modn uint32
	var y0_12, y0_13, y0_14, y0_15 byte
	var t [16]byte

	if len(cipher_text) < len(plain_text) {
		return false
	}

	// Compute nonce prefix
	if len(nonce) == 12 {
		for i = 0; i < 12; i++ {
			this.n[i] = nonce[i]
		}
		this.n[12] = 0
		this.n[13] = 0
		this.n[14] = 0
		this.n[15] = 1
		c = 1
	} else {
		this.ghash(t[:], nil, nonce)
		for i = 0; i < 16; i++ {
			this.n[i] = t[i]
		}
		y0_12 = this.n[12]
		y0_13 = this.n[13]
		y0_14 = this.n[14]
		y0_15 = this.n[15]
		c = (uint32(y0_12) << 24) | (uint32(y0_13) << 16) | (uint32(y0_14) << 8) | uint32(y0_15)
	}

	this.ghash(t[:], associated_data, cipher_text)
	// Compute Y0
	// Compute E(K,Y0)
	this.cipher.Encrypt(this.y[:], this.n[:])
	// Compute and compare GHASH^E(K,Y0)
	for i = 0; i < 16; i++ {
		if tag[i] != (t[i] ^ this.y[i]) {
			return false
		}
	}

	// Decryption of the cipher text
	n = uint32(len(cipher_text))
	modn = n & 0xf
	n >>= 4
	for i = 0; i < n; i++ {
		// Compute Yi = incr(Yi−1)
		c++
		this.n[15] = byte(c & 0xff)
		this.n[14] = byte((c >> 8) & 0xff)
		this.n[13] = byte((c >> 16) & 0xff)
		this.n[12] = byte((c >> 24) & 0xff)
		// Compute E(K,Yi)
		this.cipher.Encrypt(this.y[:], this.n[:])
		// Compute Ci = Pi xor E(K,Yi)
		for j = 0; j < 16; j++ {
			plain_text[(i<<4)+j] = cipher_text[(i<<4)+j] ^ this.y[j]
		}
	}
	if modn > 0 {
		// Compute Yn = incr(Yn−1)
		c++
		this.n[15] = byte(c & 0xff)
		this.n[14] = byte((c >> 8) & 0xff)
		this.n[13] = byte((c >> 16) & 0xff)
		this.n[12] = byte((c >> 24) & 0xff)
		// Compute E(K,Yn)
		this.cipher.Encrypt(this.y[:], this.n[:])
		// Compute Cn = Pn xor MSBv( E(K,Yn) )
		for j = 0; j < modn; j++ {
			plain_text[(n<<4)+j] = cipher_text[(n<<4)+j] ^ this.y[j]
		}
	}
	return true
}

func (this *aesGcm) ghash(tag []byte, a, c []byte) {

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
	var i, j, k uint32

	m := uint32(len(a))
	modm := m & 0xf
	v := uint64(m) << 3
	m >>= 4

	n := uint32(len(c))
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
			a1 += uint64(a[(i<<4)+j]) << (56 - (j << 3))
		}
		for j = 8; j < 16; j++ {
			a0 += uint64(a[(i<<4)+j]) << (56 - ((j - 8) << 3))
		}
		// Compute Xi = (Xi−1 xor Ai) * H
		x0, x1 = this.multH(x0^a0, x1^a1)
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
			a1 += uint64(a[(m<<4)+j]) << (56 - (j << 3))
		}
		if modm > 8 {
			k = modm
			for j = 8; j < k; j++ {
				a0 += uint64(a[(m<<4)+j]) << (56 - ((j - 8) << 3))
			}
		}
		// Compute Xm = (Xm-1 xor (Am || 0^(128−v)) * H
		x0, x1 = this.multH(x0^a0, x1^a1)
	}

	// STEP 4: Compute Xm+1 to Xm+n-1
	for i = 0; i < n; i++ {
		// Compute Ci (= little endian uint128 in two uint64)
		a0 = 0
		a1 = 0
		for j = 0; j < 8; j++ {
			a1 += uint64(c[(i<<4)+j]) << (56 - (j << 3))
		}
		for j = 8; j < 16; j++ {
			a0 += uint64(c[(i<<4)+j]) << (56 - ((j - 8) << 3))
		}
		// Compute Xi = (Xi−1 xor Ci−m) * H
		x0, x1 = this.multH(x0^a0, x1^a1)
	}

	// STEP 5: Compute Xm+n = (Xm+n-1 xor (Cn||0^(128−u)) * H
	if modn > 0 {
		a0 = 0
		a1 = 0
		// Compute Cn (= little endian uint128 in two uint64)
		if modn < 8 {
			k = modn
		} else {
			k = 8
		}
		for j = 0; j < k; j++ {
			a1 += uint64(c[(n<<4)+j]) << (56 - (j << 3))
		}
		if modn > 8 {
			k = modn
			for j = 8; j < k; j++ {
				a0 += uint64(c[(n<<4)+j]) << (56 - ((j - 8) << 3))
			}
		}
		// Compute Xm+n = (Xm+n-1 xor (Cn||0^(128−u)) * H
		x0, x1 = this.multH(x0^a0, x1^a1)
	}

	// STEP 6: Xm+n+1 = (Xm+n xor (len(A) || len(C))) * H
	x0, x1 = this.multH(x0^u, x1^v)

	// Write GHASH as Little Endian
	for i = 0; i < 8; i++ {
		tag[i] = byte(x1 >> (56 - (i << 3)))
	}
	for i = 0; i < 8; i++ {
		tag[i+8] = byte(x0 >> (56 - (i << 3)))
	}
}

func (this *aesGcm) multH(x0, x1 uint64) (z0, z1 uint64) {

	// Multiplication in Galois Field (2^128): Computes the value of Z = X * Y, where X,Y and Z are one of GF(2^128).
	//
	// Z = 0
	// V = X
	// R = 11100001 || 0^120
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

	var i uint32
	// z0 = z1 = 0 (default uint64 value)

	v0 := x0
	v1 := x1
	y0 := this.h0
	y1 := this.h1

	for i = 0; i < 64; i++ {
		//   if Yi = 1 then Z = Z xor V
		if (y1 & (1 << (63 - i))) > 0 {
			z0 ^= v0
			z1 ^= v1
		}
		//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
		if (v0 & 1) == 0 {
			v0 >>= 1
			if (v1 & 1) == 1 {
				v0 |= 0x8000000000000000
			}
			v1 >>= 1
		} else {
			v0 >>= 1
			if (v1 & 1) == 1 {
				v0 |= 0x8000000000000000
			}
			v1 >>= 1
			v1 ^= 0xe100000000000000
			v0 ^= 0
		}
	}
	for i = 0; i < 64; i++ {
		//   if Yi = 1 then Z = Z xor V
		if (y0 & (1 << (63 - i))) > 0 {
			z0 ^= v0
			z1 ^= v1
		}
		//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
		if (v0 & 1) == 0 {
			v0 >>= 1
			if (v1 & 1) == 1 {
				v0 |= 0x8000000000000000
			}
			v1 >>= 1
		} else {
			v0 >>= 1
			if (v1 & 1) == 1 {
				v0 |= 0x8000000000000000
			}
			v1 >>= 1
			v1 ^= 0xe100000000000000
			v0 ^= 0
		}
	}
	return
}
