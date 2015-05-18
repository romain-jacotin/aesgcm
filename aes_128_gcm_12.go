package main

import "crypto/aes"
import "crypto/cipher"

import "strings"
import "fmt"

type AesGcm struct {
	cipher cipher.Block
	y      []byte
	n      []byte
	h0     uint64
	h1     uint64
}

func NewAesGcm(key []byte) *AesGcm {
	var err error
	var i uint32

	a := new(AesGcm)
	h := make([]byte, 16)
	a.y = make([]byte, 16)
	a.n = make([]byte, 16)

	a.cipher, err = aes.NewCipher(key)
	if err != nil {
		fmt.Printf("crypto.aes.NewCipher( []byte ) error\n")
		return nil
	}

	a.cipher.Encrypt(h, a.y)
	for i = 0; i < 8; i++ {
		a.h1 += uint64(h[i]) << (56 - (i << 3))
	}
	for i = 0; i < 8; i++ {
		a.h0 += uint64(h[i+8]) << (56 - (i << 3))
	}
	return a
}

func (this *AesGcm) EncryptThenMac(tag, cipher_text, associated_data, plain_text, nonce []byte) bool {

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
	var null []byte

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
		this.Ghash(tag, null, nonce)
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
		fmt.Printf("[Y%d]            = %x\n", c-1, this.n)
		// Compute E(K,Yi)
		this.cipher.Encrypt(this.y, this.n)
		fmt.Printf("[E(K,Y%d)]       = %x\n", c-1, this.y)
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
		fmt.Printf("[Y%d]            = %x\n", c-1, this.n)
		// Compute E(K,Yn)
		this.cipher.Encrypt(this.y, this.n)
		fmt.Printf("[E(K,Y%d)]       = %x\n", c-1, this.y)
		// Compute Cn = Pn xor MSBv( E(K,Yn) )
		for j = 0; j < modn; j++ {
			cipher_text[(n<<4)+j] = plain_text[(n<<4)+j] ^ this.y[j]
		}
	}

	fmt.Printf("[H]             = %x %x\n", this.h1, this.h0)
	this.Ghash(tag, associated_data, cipher_text)
	fmt.Printf("[GHASH]         = %x\n", tag)
	// Compute Y0
	this.n[12] = y0_12
	this.n[13] = y0_13
	this.n[14] = y0_14
	this.n[15] = y0_15
	fmt.Printf("[Y0]            = %x\n", this.n)
	// Compute E(K,Y0)
	this.cipher.Encrypt(this.y, this.n)
	fmt.Printf("[E(K,Y0)]       = %x\n", this.y)
	// Compute GHASH^E(K,Y0)
	for i = 0; i < 16; i++ {
		tag[i] ^= this.y[i]
	}
	fmt.Printf("[GHASH^E(K,Y0)] = %x\n\n", tag)
	return true
}

func (this *AesGcm) AuthenticateThenDecrypt(tag, plain_text, associated_data, cipher_text, nonce []byte) bool {

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
	var null []byte
	t := make([]byte, 16)

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
		this.Ghash(t, null, nonce)
		for i = 0; i < 16; i++ {
			this.n[i] = t[i]
		}
		y0_12 = this.n[12]
		y0_13 = this.n[13]
		y0_14 = this.n[14]
		y0_15 = this.n[15]
		c = (uint32(y0_12) << 24) | (uint32(y0_13) << 16) | (uint32(y0_14) << 8) | uint32(y0_15)
	}

	fmt.Printf("[H]             = %x %x\n", this.h1, this.h0)
	this.Ghash(t, associated_data, cipher_text)
	fmt.Printf("[GHASH]         = %x\n", t)
	// Compute Y0
	fmt.Printf("[Y0]            = %x\n", this.n)
	// Compute E(K,Y0)
	this.cipher.Encrypt(this.y, this.n)
	fmt.Printf("[E(K,Y0)]       = %x\n", this.y)
	// Compute and compare GHASH^E(K,Y0)
	for i = 0; i < 16; i++ {
		t[i] ^= this.y[i]
		if tag[i] != t[i] {
			return false
		}
	}
	fmt.Printf("[GHASH^E(K,Y0)] = %x\n", t)

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
		fmt.Printf("[Y%d]            = %x\n", c-1, this.n)
		// Compute E(K,Yi)
		this.cipher.Encrypt(this.y, this.n)
		fmt.Printf("[E(K,Y%d)]       = %x\n", c-1, this.y)
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
		fmt.Printf("[Y%d]            = %x\n", c-1, this.n)
		// Compute E(K,Yn)
		this.cipher.Encrypt(this.y, this.n)
		fmt.Printf("[E(K,Y%d)]       = %x\n", c-1, this.y)
		// Compute Cn = Pn xor MSBv( E(K,Yn) )
		for j = 0; j < modn; j++ {
			plain_text[(n<<4)+j] = cipher_text[(n<<4)+j] ^ this.y[j]
		}
	}
	fmt.Printf("\n")
	return true
}

func (this *AesGcm) Ghash(tag []byte, a, c []byte) {

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
		fmt.Printf("[X%d]            = %x %x\n", i+1, x1, x0)
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
		fmt.Printf("[X%d]            = %x %x\n", m, x1, x0)
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
		fmt.Printf("[X%d]            = %x %x\n", m+i+1, x1, x0)
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
		fmt.Printf("[X%d]            = %x %x\n", m+n, x1, x0)
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

func (this *AesGcm) multH(x0, x1 uint64) (z0, z1 uint64) {

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

func main() {
	var null []byte

	// Test Case 1 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("00000000000000000000000000000000"), // key
		toByte("000000000000000000000000"),         // nonce
		null, // aad
		null, // plain text
		null, // waiting cipher
		toByte("58e2fccefa7e3061367f1d57a4e7455a")) // waiting tag

	// Test Case 2 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("00000000000000000000000000000000"), // key
		toByte("000000000000000000000000"),         // nonce
		null, // aad
		toByte("00000000000000000000000000000000"), // plain text
		toByte("0388dace60b6a392f328c2b971b2fe78"), // waiting cipher
		toByte("ab6e47d42cec13bdf53a67b21257bddf")) // waiting tag

	// Test Case 3 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308"), // key
		toByte("cafebabefacedbaddecaf888"),         // nonce
		null, // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"), // plain text
		toByte("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"), // waiting cipher
		toByte("4d5c2af327cd64a62cf35abd2ba6fab4"))                                                                                                 // waiting tag

	// Test Case 4 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308"),                                                                                         // key
		toByte("cafebabefacedbaddecaf888"),                                                                                                 // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"), // waiting cipher
		toByte("5bc94fbc3221a5db94fae95ae7121a47"))                                                                                         // waiting tag

	// Test Case 5 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308"),                                                                                         // key
		toByte("cafebabefacedbad"),                                                                                                         // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598"), // waiting cipher
		toByte("3612d2e79e3b0785561be14aaca2fccb"))                                                                                         // waiting tag

	// Test Case 6 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308"),                                                                                         // key
		toByte("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"), // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5"), // waiting cipher
		toByte("619cc5aefffe0bfa462af43c1699d050"))                                                                                         // waiting tag

	// Test Case 7 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("000000000000000000000000000000000000000000000000"), // key
		toByte("000000000000000000000000"),                         // nonce
		null, // aad
		null, // plain text
		null, // waiting cipher
		toByte("cd33b28ac773f74ba00ed1f312572435")) // waiting tag

	// Test Case 8 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("000000000000000000000000000000000000000000000000"), // key
		toByte("000000000000000000000000"),                         // nonce
		null, // aad
		toByte("00000000000000000000000000000000"), // plain text
		toByte("98e7247c07f0fe411c267e4384b0f600"), // waiting cipher
		toByte("2ff58d80033927ab8ef4d4587514f0fb")) // waiting tag

	// Test Case 9 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c"), // key
		toByte("cafebabefacedbaddecaf888"),                         // nonce
		null, // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"), // plain text
		toByte("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256"), // waiting cipher
		toByte("9924a7c8587336bfb118024db8674a14"))                                                                                                 // waiting tag

	// Test Case 10 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c"),                                                                         // key
		toByte("cafebabefacedbaddecaf888"),                                                                                                 // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710"), // waiting cipher
		toByte("2519498e80f1478f37ba55bd6d27618c"))                                                                                         // waiting tag

	// Test Case 11 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c"),                                                                         // key
		toByte("cafebabefacedbad"),                                                                                                         // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7"), // waiting cipher
		toByte("65dcc57fcf623a24094fcca40d3533f8"))                                                                                         // waiting tag

	// Test Case 12 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c"),                                                                         // key
		toByte("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"), // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b"), // waiting cipher
		toByte("dcf566ff291c25bbb8568fc3d376a6d9"))                                                                                         // waiting tag

	// Test Case 13 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("0000000000000000000000000000000000000000000000000000000000000000"), // key
		toByte("000000000000000000000000"),                                         // nonce
		null, // aad
		null, // plain text
		null, // waiting cipher
		toByte("530f8afbc74536b9a963b4f1c4cb738b")) // waiting tag

	// Test Case 14 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("0000000000000000000000000000000000000000000000000000000000000000"), // key
		toByte("000000000000000000000000"),                                         // nonce
		null, // aad
		toByte("00000000000000000000000000000000"), // plain text
		toByte("cea7403d4d606b6e074ec5d3baf39d18"), // waiting cipher
		toByte("d0d1c8a799996bf0265b98b5d48ab919")) // waiting tag

	// Test Case 15 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"), // key
		toByte("cafebabefacedbaddecaf888"),                                         // nonce
		null, // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"), // plain text
		toByte("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"), // waiting cipher
		toByte("b094dac5d93471bdec1a502270e3cc6c"))                                                                                                 // waiting tag

	// Test Case 16 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),                                                         // key
		toByte("cafebabefacedbaddecaf888"),                                                                                                 // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"), // waiting cipher
		toByte("76fc6ece0f4e1768cddf8853bb2d551b"))                                                                                         // waiting tag

	// Test Case 17 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),                                                         // key
		toByte("cafebabefacedbad"),                                                                                                         // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f"), // waiting cipher
		toByte("3a337dbf46a792c45e454913fe2ea8f2"))                                                                                         // waiting tag

	// Test Case 18 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	test_AES_GCM(
		toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),                                                         // key
		toByte("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"), // nonce
		toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
		toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
		toByte("5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f"), // waiting cipher
		toByte("a44a8266ee1c8eb0c8b5d4cf5ae9f19a"))                                                                                         // waiting tag
}

func toByte(s string) []byte {
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
	return b
}

func test_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag []byte) {
	fmt.Printf("\n~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\n\n")
	testEncrypt_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag)
	testDecrypt_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag)
}

func testEncrypt_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag []byte) {
	t := make([]byte, len(tag))
	ct := make([]byte, len(plaintext))
	aead := NewAesGcm(key)

	fmt.Printf("----------------\nENCRYPTION TEST:\n----------------\n")
	fmt.Printf("Key             : [%d] %x\n", len(key), key)
	fmt.Printf("Nonce           : [%d] %x\n", len(nonce), nonce)
	fmt.Printf("Associated data : [%d] %x\n", len(aad), aad)
	fmt.Printf("Plain text      : [%d] %x\n\n", len(plaintext), plaintext)
	aead.EncryptThenMac(t, ct, aad, plaintext, nonce)
	fmt.Printf("Cipher text     : [%d] %x\n", len(ct), ct)
	fmt.Printf("< Waiting cipher >[%d] %x\n\n", len(ciphertext), ciphertext)
	fmt.Printf("Tag             : [%d] %x\n", len(t), t)
	fmt.Printf("<   Waiting tag  >[%d] %x\n\n", len(tag), tag)
}

func testDecrypt_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag []byte) {
	pt := make([]byte, len(ciphertext))
	aead := NewAesGcm(key)

	fmt.Printf("----------------\nDECRYPTION TEST:\n----------------\n")
	fmt.Printf("Key             : [%d] %x\n", len(key), key)
	fmt.Printf("Nonce           : [%d] %x\n", len(nonce), nonce)
	fmt.Printf("Associated data : [%d] %x\n", len(aad), aad)
	fmt.Printf("Cipher text     : [%d] %x\n", len(ciphertext), ciphertext)
	fmt.Printf("Tag             : [%d] %x\n\n", len(tag), tag)
	fmt.Printf("Authenticate    ?      %v\n\n", aead.AuthenticateThenDecrypt(tag, pt, aad, ciphertext, nonce))
	fmt.Printf("Plain text      : [%d] %x\n", len(pt), pt)
	fmt.Printf("< Waiting Plain > [%d] %x\n\n", len(plaintext), plaintext)
}
