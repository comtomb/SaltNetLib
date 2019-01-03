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

using System;
using System.Globalization;
using System.IO;
using TomB.Util;

namespace TomB.SaltNet.Curve25519
{
    /// <summary>
    /// Abstract base class for Curve25519 implementation
    /// 
    /// this class implements all "nice" methods around the actual scalar multiplication <see cref="AbstractCurve25519.ScalarMultiplicationRaw(byte[], int, byte[], int, byte[], int)"/>. 
    /// </summary>
    internal abstract class AbstractCurve25519 : ICurve25519
    {
        public const int KeyLength = 32;
        /// <summary>
        /// base in LE byte[]
        /// </summary>
        private static readonly byte[] uBase = new byte[] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        /// <summary>
        /// <see cref="ICurve25519.KeyLen"/>
        /// </summary>
        public int KeyLen
        {
            get
            {
                return KeyLength;
            }
        }

        /// <summary>
        /// <see cref="ICurve25519.CreateKeyPair(byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyOfs"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyOfs"></param>
        /// <returns></returns>
        public int CreateKeyPair(byte[] publicKey, int publicKeyOfs, byte[] privateKey, int privateKeyOfs)
        {
            if (privateKey == null || publicKey == null)
                throw new ArgumentNullException();
            if (publicKeyOfs < 0 || privateKeyOfs < 0)
                throw new ArgumentException();
            if( publicKey.Length-publicKeyOfs<KeyLength || privateKey.Length-privateKeyOfs<KeyLength)
                throw new ArgumentException();

            var sr = new SecureRandom();
            sr.Randomize(privateKey, privateKeyOfs, KeyLength);
            return CreatePublicKeyFromPrivateKey(publicKey, publicKeyOfs, privateKey, privateKeyOfs);
        }
        /// <summary>
        /// <see cref="ICurve25519.CreateKeyPair(out byte[], out byte[])"/>
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public int CreateKeyPair(out byte[] publicKey, out byte[] privateKey)
        {
            publicKey = new byte[KeyLength];
            privateKey = new byte[KeyLength];
            return CreateKeyPair(publicKey, 0, privateKey, 0);
        }

        /// <summary>
        /// <see cref="ICurve25519.CreatePublicKeyFromPrivateKey(byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyOfs"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyOfs"></param>
        /// <returns></returns>
        public int CreatePublicKeyFromPrivateKey(byte[] publicKey, int publicKeyOfs, byte[] privateKey, int privateKeyOfs)
        {
            return ScalarMultiplicationBase(publicKey, publicKeyOfs, privateKey, privateKeyOfs);
        }
        /// <summary>
        /// <see cref="ICurve25519.ScalarMultiplication(byte[], int, byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="res"></param>
        /// <param name="resOfs"></param>
        /// <param name="u"></param>
        /// <param name="uOfs"></param>
        /// <param name="scalar"></param>
        /// <param name="scalarOfs"></param>
        /// <returns></returns>
        public int ScalarMultiplication(byte[] res, int resOfs, byte[] u, int uOfs, byte[] scalar, int scalarOfs)
        {
            if (res == null || u == null || scalar == null)
                throw new ArgumentNullException();
            if (resOfs < 0 || uOfs < 0 || scalarOfs < 0)
                throw new ArgumentException();
            if (res.Length - resOfs < KeyLength || u.Length - uOfs < KeyLength || scalar.Length - scalarOfs < KeyLength)
                throw new ArgumentException();

            byte[] cpyS = new byte[KeyLength];
            Array.Copy(scalar, scalarOfs, cpyS, 0, KeyLength);
            // some bit manipulation, see RFC 7748 chapter 5
            cpyS[0] &= 248;
            cpyS[31] &= 127;
            cpyS[31] |= 64;
            byte[] cpyU = new byte[KeyLength];
            Array.Copy(u, uOfs, cpyU, 0, 32);
            cpyU[31] &= 127; // for compatibilty... see RFC 7748 chapter 5

            return ScalarMultiplicationRaw(res, resOfs, cpyU, 0, cpyS, 0);
        }
        /// <summary>
        /// <see cref="ICurve25519.ScalarMultiplicationBase(byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="res"></param>
        /// <param name="resOfs"></param>
        /// <param name="scalar"></param>
        /// <param name="scalarOfs"></param>
        /// <returns></returns>
        public int ScalarMultiplicationBase(byte[] res, int resOfs, byte[] scalar, int scalarOfs)
        {
            return ScalarMultiplication(res, resOfs, uBase, 0, scalar, scalarOfs);
        }
        /// <summary>
        /// check if two byte arrays are equal (same content, same length)
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <exception cref="Exception"> if arrays are not equal</exception>
        private void ArrayEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new Exception();
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i])
                    throw new Exception();
        } 
        /// <summary>
        /// validation loop according to the standard (debugging only)
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="maxLoops"></param>
        /// <returns></returns>
        public long Validation(TextWriter writer, int maxLoops)
        {
            DateTime now = DateTime.Now;
            byte[] u = ByteUtil.HexToByteArray("0900000000000000000000000000000000000000000000000000000000000000");
            byte[] k = (byte[])u.Clone();

            byte[] k1 = ByteUtil.HexToByteArray("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
            byte[] k1000 = ByteUtil.HexToByteArray("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
            // add on
            byte[] k10000 = ByteUtil.HexToByteArray("2C125A20F639D504A7703D2E223C79A79DE48C4EE8C23379AA19A62ECD211815");
            byte[] k1000000 = ByteUtil.HexToByteArray("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");

            int c = 0;

            if (maxLoops <= 0 || maxLoops == Int32.MaxValue)
                maxLoops = 1000000;      // thats the value from the standard
            DateTime t0 = DateTime.Now;
            writer.WriteLine("performing " + maxLoops + " iterations");
            for (int i = 1; i <= maxLoops; i++)
            {
                byte[] h = new byte[32];
                ScalarMultiplication(h, 0, u, 0, k, 0);
                u = k;
                k = h;
                if ((i % 100) == 0)
                {
                    DateTime tn = DateTime.Now;
                    TimeSpan elapsed = TimeSpan.FromTicks(tn.Ticks - t0.Ticks);
                    long rate = (long)((i * 1000) / elapsed.TotalMilliseconds);
                    writer.WriteLine(i + " " + ByteUtil.BytesToHexString(k) + "-> elapsed: " + elapsed + " rate: " + rate + "/s");
                }
                if (i == 1)
                {
                    c++;
                    ArrayEqual(k, k1);
                }
                if (i == 1000)
                {
                    c++;
                    ArrayEqual(k, k1000);
                }
                if (i == 10000)
                {
                    ArrayEqual(k, k10000);
                }
                if (i == 1000000)
                {
                    c++;
                    ArrayEqual(k, k1000000);
                }
            }
            TimeSpan elapsedAll = TimeSpan.FromTicks(DateTime.Now.Ticks - now.Ticks);
            writer.WriteLine("elapsed: " + elapsedAll.TotalMilliseconds);
            return (long)elapsedAll.TotalMilliseconds;
        }

        /// <summary>
        /// <see cref="ICurve25519.ScalarMultiplicationRaw(byte[], int, byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="res"></param>
        /// <param name="resOfs"></param>
        /// <param name="u"></param>
        /// <param name="uOfs"></param>
        /// <param name="k"></param>
        /// <param name="kOfs"></param>
        /// <returns></returns>
        public abstract int ScalarMultiplicationRaw(byte[] res, int resOfs, byte[] u, int uOfs, byte[] k, int kOfs);


    }
}
