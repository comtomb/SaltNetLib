/*
MIT License

Copyright (c) 2019 comtomb [TomB]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
using TomB.SaltNetLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TomB.SaltNet
{
    // TODO rework documentation: better explanaition of functions, parameters, length

    /// <summary>
    /// Encryption/Decryption
    ///     Key: Curve25519
    ///     Encryption:XSalsa20
    ///     MAC: Poly1305
    /// </summary>
    public interface IBoxCurve25519XSalsa20Poly1305
    {
        /// <summary>
        /// get a ICurve25519 implementation
        /// </summary>
        /// <returns>Curve25519</returns>
        ICurve25519 GetCurve25519();
        /// <summary>
        /// get a Poly1305 implementation
        /// </summary>
        /// <returns>Poly1305</returns>
        IPoly1305 GetPoly1305();
        /// <summary>
        /// return a XSalsa20 implementation
        /// </summary>
        /// <returns>xsalsa20</returns>
        IXSalsa20 GetXSalsa20();
        /// <summary>
        /// return a ISecureRandom implementation
        /// </summary>
        /// <returns></returns>
        ISecureRandom GetSecureRandom();
        /// <summary>
        /// Encrypt and MAC an expandend block. 
        /// 
        /// use <see cref="IBoxCurve25519XSalsa20Poly1305.EncryptSymmetric(byte[], int, byte[], int, byte[], int, byte[], int, int)"/> instead
        /// Encrypt and mac an (expanded) message
        /// after this call the content of c is:
        ///   0 - 15: undefined
        ///  16 - 31: Poly1305 MAC
        ///  32 - msgLen: encrypted message
        /// </summary>
        /// <param name="c"></param>
        /// <param name="cOfs"></param>
        /// <param name="msg">msg must start with 32 bytes of 0</param>
        /// <param name="msgOfs"></param>
        /// <param name="msgLen">message length (including 32 bytes from expansion)</param>
        /// <param name="nonce">24 byte nonce</param>
        /// <param name="nonceOfs"></param>
        /// <param name="sharedKey"></param>
        /// <param name="sharedKeyOfs"></param>
        void AfterNm(byte[] c, int cOfs, byte[] msg, int msgOfs, int msgLen, byte[] nonce, int nonceOfs, byte[] sharedKey, int sharedKeyOfs);
        /// <summary>
        /// decrypt  an expanded block
        /// 
        /// use <see cref="IBoxCurve25519XSalsa20Poly1305.DecryptSymmetric(byte[], int, byte[], int, byte[], int, byte[], int, int)"/> instead
        /// </summary>
        /// <param name="msg">decrypted message (cLen-16) bytes</param>
        /// <param name="msgOfs">start of decrypted message</param>
        /// <param name="c">encrypted message</param>
        /// <param name="cOfs">start of encrypted message</param>
        /// <param name="cLen">length of encrypted message (incl. 16 byte MAC)</param>
        /// <param name="nonce">nonce (24 bytes)</param>
        /// <param name="nonceOfs">start of nonce</param>
        /// <param name="sharedKey">shared key (32 bytes)</param>
        /// <param name="sharedKeyOfs">start of shared</param>
        void OpenAfterNm(byte[] msg,int msgOfs, byte[] c, int cOfs,int cLen, byte[] nonce,int nonceOfs,byte[] sharedKey,int sharedKeyOfs);
        
        /// <summary>
        /// Decrypt a message
        /// </summary>
        /// <param name="decryptedData"></param>
        /// <param name="decryptedDataOfs"></param>
        /// <param name="sharedKey"></param>
        /// <param name="sharedKeyOfs"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="encryptedData"></param>
        /// <param name="encryptedDataOfs"></param>
        /// <param name="encryptedDataLen"></param>
        void DecryptSymmetric(byte[] decryptedData,int decryptedDataOfs,byte[] sharedKey, int sharedKeyOfs, byte[] nonce, int nonceOfs, byte[] encryptedData, int encryptedDataOfs, int encryptedDataLen);
        /// <summary>
        /// Encrypt a message
        /// </summary>
        /// <param name="encryptedData">buffer to receive plainDataLen+16 bytes encrypted data</param>
        /// <param name="encryptedDataOfs">offset in bufer</param>
        /// <param name="sharedKey">shared key</param>
        /// <param name="sharedKeyOfs"></param>
        /// <param name="nonce">Nonce</param>
        /// <param name="nonceOfs"></param>
        /// <param name="plainData">plain data</param>
        /// <param name="plainDataOfs"></param>
        /// <param name="plainDataLen"></param>
        void EncryptSymmetric(byte[] encryptedData,int encryptedDataOfs,byte[] sharedKey,int sharedKeyOfs, byte[] nonce, int nonceOfs,byte[] plainData,int plainDataOfs,int plainDataLen);
        /// <summary>
        /// Shared Key calculation
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="sharedKeyOfs"></param>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyOfs"></param>
        /// <param name="secretKey"></param>
        /// <param name="secretKeyOfs"></param>
        void BeforeNm(byte[] sharedKey,int sharedKeyOfs,byte[] publicKey, int publicKeyOfs, byte[] secretKey, int secretKeyOfs);
        /// <summary>
        /// Shared Key calculation
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        byte[] BeforeNm(byte[] publicKey, byte[] secretKey);

        /// <summary>
        /// Encrypt a message
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="nonce"></param>
        /// <param name="plainData"></param>
        /// <returns></returns>
        byte[] EncryptSymmetric(byte[] sharedKey, byte[] nonce, byte[] plainData);
        /// <summary>
        /// Decrypt a message
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="nonce"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        byte[] DecryptSymmetric(byte[] sharedKey, byte[] nonce, byte[] encryptedData);
        /// <summary>
        /// Asynchronous Encrypt
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="nonce"></param>
        /// <param name="plainData"></param>
        /// <returns></returns>
        Task<byte[]> EncryptSymmetricAsync(byte[] sharedKey, byte[] nonce, byte[] plainData);
        /// <summary>
        /// Asynchronous Decrypt
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="nonce"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        Task<byte[]> DecryptSymmetricAsync(byte[] sharedKey, byte[] nonce, byte[] encryptedData);
        /// <summary>
        /// Create a Keypair
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyOfs"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyOfs"></param>
        void CreateKeyPair(byte[] publicKey, int publicKeyOfs, byte[] privateKey, int privateKeyOfs);
        /// <summary>
        /// Create a Keypair
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        void CreateKeyPair(out byte[] publicKey, out byte[] privateKey);

        /// <summary>
        /// Debugging... return a 'hello' string
        /// </summary>
        /// <returns></returns>
        string GetHello();


    }
}
