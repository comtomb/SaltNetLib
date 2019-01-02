using System.Diagnostics;
using TomB.SaltNet.Curve25519;
using TomB.SaltNet.Poly1305;
using TomB.SaltNet.Salsa20;
using System;
using System.Threading.Tasks;
using TomB.SaltNetLib;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SaltNetTest")]

namespace TomB.SaltNet
{
    /// <summary>
    /// CryptoBox implementation
    /// </summary>
    internal class BoxCurve25519XSalsa20Poly1305 : IBoxCurve25519XSalsa20Poly1305
    {
        /// <summary>
        /// curve25519
        /// </summary>
        private ICurve25519 curve25519;
        /// <summary>
        /// poly1305
        /// </summary>
        private IPoly1305 poly1305;
        /// <summary>
        /// xsalsa20
        /// </summary>
        private IXSalsa20 xsalsa20;
        /// <summary>
        /// secure random
        /// </summary>
        private ISecureRandom secureRandom;

        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.AfterNm(byte[], int, byte[], int, int, byte[], int, byte[], int)"/>
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
        public void AfterNm(byte[] c, int cOfs, byte[] msg, int msgOfs, int msgLen, byte[] nonce, int nonceOfs, byte[] sharedKey, int sharedKeyOfs)
        {
            if (c == null || msg == null || nonce == null || sharedKey == null)
                throw new ArgumentNullException();
            if (cOfs < 0 || msgOfs < 0 || nonceOfs < 0 || sharedKeyOfs < 0)
                throw new ArgumentException();
            if (c.Length - cOfs < msgLen || msg.Length-msgOfs<msgLen || nonce.Length-nonceOfs<24 || sharedKey.Length-sharedKeyOfs<32)
                throw new ArgumentException();

            // encrypt
            GetXSalsa20().XSalsa20XorIC(c, cOfs, msg, msgOfs, msgLen, nonce, nonceOfs, sharedKey, 0, null, 0);

            // mac            
            GetPoly1305().Poly1305(c, cOfs + 16, c, cOfs + 32, msgLen - 32, c, cOfs);
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.OpenAfterNm(byte[], int, byte[], int, int, byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="msgOfs"></param>
        /// <param name="c"></param>
        /// <param name="cOfs"></param>
        /// <param name="cLen"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="sharedKey"></param>
        /// <param name="sharedKeyOfs"></param>
        public void OpenAfterNm(byte[] msg,int msgOfs, byte[] c, int cOfs,int cLen, byte[] nonce,int nonceOfs,byte[] sharedKey,int sharedKeyOfs)
        {
            if (c == null || msg == null || nonce == null || sharedKey == null)
                throw new ArgumentNullException();
            if (cOfs < 0 || msgOfs < 0 || nonceOfs < 0 || sharedKeyOfs < 0)
                throw new ArgumentException();
            if (msg.Length - msgOfs < cLen - 16 || nonce.Length - nonceOfs < 24 || sharedKey.Length - sharedKeyOfs < 32)
                throw new ArgumentException();

            
            // subkey
            var subkey = new byte[32];
            GetXSalsa20().HSalsa20(subkey, 0, nonce, 0, sharedKey, 0, null, 0);
		    
            // Poly1305 check
            var poly1305Key=new byte[32];
            GetXSalsa20().Salsa20(poly1305Key,0,32,nonce,nonceOfs+16,subkey,0);                       

            var poly1305mac=new byte[16];
            GetPoly1305().Poly1305(poly1305mac,0,c,cOfs+32,cLen-32,poly1305Key,0);            
            for(int i=0;i<16;i++)
            	if( poly1305mac[i]!=c[cOfs+i+16])
            		throw new DecryptionException("poly1305 check failed");            
            
			// decrypt
            GetXSalsa20().Salsa20XorIC(msg,msgOfs,c,cOfs,cLen,nonce,nonceOfs+16,subkey,0,null,0);
        	
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.BeforeNm(byte[], byte[])"/>
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="sharedKeyOfs"></param>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyOfs"></param>
        /// <param name="secretKey"></param>
        /// <param name="secretKeyOfs"></param>
        public void BeforeNm(byte[] sharedKey, int sharedKeyOfs, byte[] publicKey, int publicKeyOfs, byte[] secretKey, int secretKeyOfs)
        {
            if (sharedKey == null || publicKey == null || secretKey == null)
                throw new ArgumentNullException();
            if (sharedKeyOfs < 0 || publicKeyOfs < 0 || secretKeyOfs < 0)
                throw new ArgumentException();
            if (sharedKey.Length - sharedKeyOfs < 32 || publicKey.Length - publicKeyOfs < 32 || secretKey.Length - secretKeyOfs < 32)
                throw new ArgumentException();
            var tmp = new byte[32];
            GetCurve25519().ScalarMultiplication(tmp,0,  publicKey, publicKeyOfs, secretKey, secretKeyOfs);
            GetXSalsa20().HSalsa20(sharedKey, sharedKeyOfs, new byte[16], 0, tmp, 0, null, 0);
        }

        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.DecryptSymmetric(byte[], int, byte[], int, byte[], int, byte[], int, int)"/>
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
        public void DecryptSymmetric(byte[] decryptedData, int decryptedDataOfs, byte[] sharedKey, int sharedKeyOfs, byte[] nonce, int nonceOfs, byte[] encryptedData, int encryptedDataOfs, int encryptedDataLen)
        {
            if (decryptedData == null || sharedKey == null || nonce == null || encryptedData == null)
                throw new ArgumentNullException();
            if (decryptedDataOfs < 0 || sharedKeyOfs < 0 || nonceOfs < 0 || encryptedDataOfs < 0 || encryptedDataLen < 0)
                throw new ArgumentException();
            if (decryptedData.Length - decryptedDataOfs < encryptedDataLen - 16 || sharedKey.Length-sharedKeyOfs<32 || nonce.Length-nonceOfs<24 || encryptedData.Length-encryptedDataOfs<encryptedDataLen)
                throw new ArgumentException();

			// expand encyrypted data             
            var expandedEnc=new byte[encryptedDataLen+16];
            Array.Copy(encryptedData,encryptedDataOfs,expandedEnc,16,encryptedDataLen);
            var tmpDec=new byte[encryptedDataLen+16];
           
            OpenAfterNm(tmpDec,0,expandedEnc,0,expandedEnc.Length,nonce,nonceOfs,sharedKey,sharedKeyOfs);
            
            Array.Copy(tmpDec,32,decryptedData,decryptedDataOfs,encryptedDataLen-16);
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.DecryptSymmetric(byte[], byte[], byte[])"/>
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="nonce"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        public byte[] DecryptSymmetric(byte[] sharedKey, byte[] nonce, byte[] encryptedData)
        {
            if (sharedKey == null || nonce == null || encryptedData != null)
                throw new ArgumentNullException();
            if (nonce.Length != 24 || sharedKey.Length != 32 || encryptedData.Length < 16)
                throw new ArgumentException();

            var dec=new byte[encryptedData.Length-16];
            DecryptSymmetric(dec,0,sharedKey,0,nonce,0,encryptedData,0,encryptedData.Length);
            return dec;
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.EncryptSymmetric(byte[], int, byte[], int, byte[], int, byte[], int, int)"/>
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="encryptedDataOfs"></param>
        /// <param name="sharedKey"></param>
        /// <param name="sharedKeyOfs"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="plainData"></param>
        /// <param name="plainDataOfs"></param>
        /// <param name="plainDataLen"></param>
        public void EncryptSymmetric(byte[] encryptedData, int encryptedDataOfs, byte[] sharedKey, int sharedKeyOfs, byte[] nonce, int nonceOfs, byte[] plainData, int plainDataOfs, int plainDataLen)
        {
            if (plainData == null || sharedKey == null || nonce == null || encryptedData == null)
                throw new ArgumentNullException();
            if (plainDataOfs < 0 || sharedKeyOfs < 0 || nonceOfs < 0 || encryptedDataOfs < 0 || plainDataLen < 0)
                throw new ArgumentException();
            if (encryptedData.Length - encryptedDataOfs < plainDataLen + 16 || sharedKey.Length - sharedKeyOfs < 32 || nonce.Length - nonceOfs < 24 || plainData.Length - plainDataOfs < plainDataLen)
                throw new ArgumentException();

            
            var tmpRaw = new byte[plainDataLen + 32];
            var tmpEnc = new byte[plainDataLen + 32];
            Array.Copy(plainData, plainDataOfs, tmpRaw, 32, plainDataLen);
            AfterNm(tmpEnc, 0, tmpRaw, 0, tmpRaw.Length, nonce, nonceOfs, sharedKey, sharedKeyOfs);
            Array.Copy(tmpEnc, 16, encryptedData, encryptedDataOfs, tmpEnc.Length - 16);
        }

        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.EncryptSymmetric(byte[], byte[], byte[])"/>
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="nonce"></param>
        /// <param name="plainData"></param>
        /// <returns></returns>
        public byte[] EncryptSymmetric(byte[] sharedKey, byte[] nonce, byte[] plainData)
        {
            if (sharedKey == null || nonce == null || plainData != null)
                throw new ArgumentNullException();
            if (nonce.Length != 24 || sharedKey.Length != 32 )
                throw new ArgumentException();

            byte[] encrypted = new byte[plainData.Length + 16];
            EncryptSymmetric(encrypted, 0, sharedKey, 0, nonce, 0, plainData, 0, plainData.Length);
            return encrypted;
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.GetCurve25519"/>
        /// </summary>
        /// <returns></returns>
        public ICurve25519 GetCurve25519()
        {
            if (curve25519 == null)
                curve25519 = Curve25519Factory.CreateInstance();
            return curve25519;
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.GetPoly1305"/>
        /// </summary>
        /// <returns></returns>
        public IPoly1305 GetPoly1305()
        {
            if (poly1305 == null)
                poly1305 = Poly1305Factory.CreateInstance();
            return poly1305;
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.GetXSalsa20"/>
        /// </summary>
        /// <returns></returns>
        public IXSalsa20 GetXSalsa20()
        {
            if (xsalsa20 == null)
                xsalsa20 = XSalsa20Factory.CreateInstance();
            return xsalsa20;
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.EncryptSymmetricAsync(byte[], byte[], byte[])"/>
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="nonce"></param>
        /// <param name="plainData"></param>
        /// <returns></returns>
        public async Task<byte[]> EncryptSymmetricAsync(byte[] sharedKey, byte[] nonce, byte[] plainData)
        {
            return await Task.Run(() => { return EncryptSymmetric(sharedKey, nonce, plainData); });
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.DecryptSymmetricAsync(byte[], byte[], byte[])"/>
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="nonce"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        public async Task<byte[]> DecryptSymmetricAsync(byte[] sharedKey, byte[] nonce, byte[] encryptedData)
        {
            return await Task.Run(() => { return DecryptSymmetric(sharedKey, nonce, encryptedData); });
        }
        public string GetHello()
        {
            string tfm = "";
            string cpu = "";
            string mode = "";
#if DEBUG
            mode+="DEBUG";
#endif
#if RELEASE
            mode += "RELEASE";
#endif

#if TFM_NET451
            tfm+="NET451";
#endif
#if TFM_NET462
            tfm+="NET462";
#endif
#if TFM_NET472
            tfm+="NET472";
#endif
#if TFM_NETCORE21
            tfm += "NETCORE21";
#endif
#if TFM_NETSTANDARD20
            tfm += "NETSTANDARD20";
#endif
#if CPU_ANY
            cpu += "ANYCPU";
#endif
#if CPU_X86
            cpu+="x86";
#endif
#if CPU_X64
            cpu+="x64";
#endif

            return "SaltNetLib_" + tfm + "_" + cpu + "_" + mode;
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.BeforeNm(byte[], byte[])"/>
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        public byte[] BeforeNm(byte[] publicKey, byte[] secretKey)
        {
            var sk = new byte[32];
            BeforeNm(sk, 0, publicKey, 0, secretKey, 0);
            return sk;
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.CreateKeyPair(byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyOfs"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyOfs"></param>
        public void CreateKeyPair(byte[] publicKey, int publicKeyOfs, byte[] privateKey, int privateKeyOfs)
        {
            GetCurve25519().CreateKeyPair(publicKey, publicKeyOfs, privateKey, privateKeyOfs);
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.CreateKeyPair(out byte[], out byte[])"/>
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        public void CreateKeyPair(out byte[] publicKey, out byte[] privateKey)
        {
            privateKey = new byte[32];
            publicKey = new byte[32];
            CreateKeyPair(publicKey, 0, privateKey, 0);
        }
        /// <summary>
        /// <see cref="IBoxCurve25519XSalsa20Poly1305.GetSecureRandom"/>
        /// </summary>
        /// <returns></returns>
        public ISecureRandom GetSecureRandom()
        {
            if (secureRandom == null)
                secureRandom = SecureRandomFactory.CreateInstance();
            return secureRandom;
        }
    }
}
