package main

import "github.com/romain-jacotin/aesgcm"

import "fmt"
import "strings"

func main() {

	// Creating the AEAD
	key := toByte("1948cafe1789deca1948cafe1789deca") // A 16 bytes key (128-bit) for AEAE_AES_128_GCM_12
	aead, err := aesgcm.NewAES_128_GCM_12(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt then Mac (EtM) example
	nonce := toByte("1789cafebabe1948bebefada")                           // A 12 bytes Nonce for AEAD_AES_128_GCM_12
	associateddata := []byte("The Universal Declaration of Human Rights") // The associated data
	plaintext := []byte("All human beings are born free and equal in dignity and rights. They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")

	ciphertext := make([]byte, len(plaintext)) // For storing the resulting ciphertext, must have same size as plaintext
	mac := make([]byte, 12)                    // For storing the resulting Message Authentication Code, must be 12 bytes for AEAD_AES_128_GCM_12

	fmt.Printf("\nAEAD_AES_128_GCM_12 Encryption test\n-----------------------------------\n")
	fmt.Printf("nonce           : [%d] %x\n", len(nonce), nonce)
	fmt.Printf("associated data : [%d] %s\n", len(associateddata), string(associateddata))
	fmt.Printf("Plain text      : [%d] %s\n", len(plaintext), string(plaintext))

	aead.EncryptThenMac(mac, ciphertext, associateddata, plaintext, nonce)

	fmt.Printf("Tag             : [%d] %x\n", len(mac), mac)
	fmt.Printf("Cipher text     : [%d] %x\n", len(ciphertext), ciphertext)

	// Authenticate then Decrypt
	ciphertext = toByte("f0397a87ac175a61e237c68df40e999de14189ac44ba3a82731669002dbd2a4d8fc3e6fa2facf4efc0a26b81a5724ed079858935d463d42b55060a6f688025b7de0b31777614ce174b835f35fe2d7cdb8b71e0a6ea9e5141598d5661558095f2d9a1f1a8ac4cdd802ab83419102966d2e31db373c0ef3e008d18d2f4c01f527f18af107d6967164646aa2f44b8dcc651843e301b64a52212d3226adc23a4545f1b204358bda427530920")
	plaintext = make([]byte, len(ciphertext)) // For storing the resulting plaintext, must have same size as ciphertext

	fmt.Printf("\nAEAD_AES_128_GCM_12 Decryption test\n-----------------------------------\n")
	fmt.Printf("nonce           : [%d] %x\n", len(nonce), nonce)
	fmt.Printf("associated data : [%d] %s\n", len(associateddata), string(associateddata))
	fmt.Printf("Cipher text     : [%d] %x\n", len(ciphertext), ciphertext)

	if aead.AuthenticateThenDecrypt(mac, plaintext, associateddata, ciphertext, nonce) {
		fmt.Printf("Plain text      : [%d] %s\n\n", len(plaintext), string(plaintext))
	} else {
		fmt.Printf("Decryption failed, bad Message Authentication Code\n")
	}
}

func toByte(s string) []byte {
	bs := []byte(strings.ToLower(s))
	b := make([]byte, len(bs)/2)

	if len(bs) == 0 {
		return []byte{}
	}
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
