# AEAD AES GCM in Go language

A Go program that implement the following AEAD Algorithms:

| IANA <br> AEAD Registry <br> (Numeric ID) |           Name         | Reference | Key size  | Nonce size | MAC size |
|-------------------------------------------|------------------------|-----------|-----------|------------|----------|
|        1        |   AEAD_AES_128_GCM     |   RFC5116 | 128-bit   | 96 bits    | 128 bit  |
|        2        |   AEAD_AES_256_GCM     |   RFC5116 | 256-bit   | 96 bits    | 128 bit  |
|        5        |   AEAD_AES_128_GCM_8   |   RFC5282 | 128-bit   | 96 bits    | 64 bit   |
|        6        |   AEAD_AES_256_GCM_8   |   RFC5282 | 256-bit   | 96 bits    | 64 bit   |
|        7        |   AEAD_AES_128_GCM_12  |   RFC5282 | 128-bit   | 96 bits    | 96 bit   |
|        8        |   AEAD_AES_256_GCM_12  |   RFC5282 | 256-bit   | 96 bits    | 96 bit   |

## References

NIST: The Galois/Counter Mode of Operation (GCM) - David A. McGrew, John Viega  
[http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf)

IETF RFC4116 An Interface and Algorithms for Authenticated Encryption  
[https://tools.ietf.org/html/rfc5116](https://tools.ietf.org/html/rfc5116)

IETF RFC5282  
[https://tools.ietf.org/html/rfc5282](https://tools.ietf.org/html/rfc5282)



