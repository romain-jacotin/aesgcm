package main

import "github.com/romain-jacotin/aesgcm"

import "bytes"
import "strings"
import "fmt"
import "time"

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

	/*
		testPerf(
			toByte("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),                                                         // key
			toByte("cafebabefacedbaddecaf888"),                                                                                                 // nonce
			toByte("feedfacedeadbeeffeedfacedeadbeefabaddad2"),                                                                                 // aad
			toByte("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"), // plain text
			toByte("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"), // waiting cipher
			toByte("76fc6ece0f4e1768cddf8853bb2d551b"))
	*/
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

func testPerf(key, nonce, aad, plaintext, ciphertext, tag []byte) {
	t := make([]byte, len(tag))
	ct := make([]byte, len(plaintext))
	pt := make([]byte, len(ciphertext))

	aead, _ := aesgcm.NewAES_256_GCM(key)
	start := time.Now()
	for i := 0; i < 1000000; i++ {
		aead.EncryptThenMac(t, ct, aad, plaintext, nonce)
		aead.AuthenticateThenDecrypt(tag, pt, aad, ciphertext, nonce)
	}
	end := time.Now()
	delta := end.Sub(start)
	fmt.Printf("Time = %s\n", delta)
}

func test_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag []byte) {
	fmt.Printf("\n~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\n\n")
	testEncrypt_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag)
	testDecrypt_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag)
}

func testEncrypt_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag []byte) {
	t := make([]byte, len(tag))
	ct := make([]byte, len(plaintext))
	aead := aesgcm.NewAesGcm(key)

	fmt.Printf("----------------\nENCRYPTION TEST:\n----------------\n")
	fmt.Printf("Key             : [%d] %x\n", len(key), key)
	fmt.Printf("Nonce           : [%d] %x\n", len(nonce), nonce)
	fmt.Printf("Associated data : [%d] %x\n", len(aad), aad)
	fmt.Printf("Plain text      : [%d] %x\n\n", len(plaintext), plaintext)
	aead.EncryptThenMac(t, ct, aad, plaintext, nonce)
	fmt.Printf("Cipher text     : [%d] %x\n", len(ct), ct)
	fmt.Printf("Tag             : [%d] %x\n\n", len(t), t)
	if bytes.Equal(ciphertext, ct) && bytes.Equal(tag, t) {
		fmt.Printf("    TEST STATUS = [ PASS ]\n\n")
	} else {
		fmt.Printf("    TEST STATUS = [ FAIL ]\n\n")
	}
}

func testDecrypt_AES_GCM(key, nonce, aad, plaintext, ciphertext, tag []byte) {
	pt := make([]byte, len(ciphertext))
	aead := aesgcm.NewAesGcm(key)

	fmt.Printf("----------------\nDECRYPTION TEST:\n----------------\n")
	fmt.Printf("Key             : [%d] %x\n", len(key), key)
	fmt.Printf("Nonce           : [%d] %x\n", len(nonce), nonce)
	fmt.Printf("Associated data : [%d] %x\n", len(aad), aad)
	fmt.Printf("Cipher text     : [%d] %x\n", len(ciphertext), ciphertext)
	fmt.Printf("Tag             : [%d] %x\n\n", len(tag), tag)
	fmt.Printf("Authenticate    ?      %v\n", aead.AuthenticateThenDecrypt(tag, pt, aad, ciphertext, nonce))
	fmt.Printf("Plain text      : [%d] %x\n\n", len(pt), pt)
	if bytes.Equal(plaintext, pt) {
		fmt.Printf("    TEST STATUS = [ PASS ]\n\n")
	} else {
		fmt.Printf("    TEST STATUS = [ FAIL ]\n\n")
	}
}
