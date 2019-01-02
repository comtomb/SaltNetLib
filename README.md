**SaltNetLib**

.NET Implementation of a CryptoBox with Curve25519XSalsa20Poly1305 (see NaCl or libsodium):

- Curve25519 for Key Generation
- XSalsa20 for Encryption
- Poly1305 for MAC



This implements some functions as used by the popular NaCl and libsodium libraries

Messages can be easily encrypted/decrypted: see example in Subproject "`RunnerCore`"



--- warning---

This library was created as a "proof of concept". (mainly to understand some cryptography principles). It runs stable an produces the same output as libsodium (see subproject "`SaltNSodiumStress`")

The implementation is vulnerable to side channel attacks (not time constant, potential key leaking)

Any feedback on how to improve this is very welome

