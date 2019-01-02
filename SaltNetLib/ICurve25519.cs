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
using System.Collections.Generic;
using System.Text;

namespace TomB.SaltNet
{
    /// <summary>
    /// Curve25519
    /// </summary>
    public interface ICurve25519
    {
        /// <summary>
        /// length of a key (32 bytes)
        /// </summary>
        int KeyLen { get; }

        /// <summary>
        /// Scalar Multiplication u*k (without manipulation of bits in u or k) 
        /// </summary>
        /// <param name="res"></param>
        /// <param name="resOfs"></param>
        /// <param name="u"></param>
        /// <param name="uOfs"></param>
        /// <param name="k"></param>
        /// <param name="kOfs"></param>
        /// <returns></returns>
        int ScalarMultiplicationRaw(byte[] res, int resOfs, byte[] u, int uOfs, byte[] k, int kOfs);
        /// <summary>
        /// ScalarMultiplication u*k according RFC7748 
        /// </summary>
        /// <param name="res"></param>
        /// <param name="resOfs"></param>
        /// <param name="u"></param>
        /// <param name="uOfs"></param>
        /// <param name="scalar"></param>
        /// <param name="scalarOfs"></param>
        /// <returns></returns>
        int ScalarMultiplication(byte[] res, int resOfs, byte[] u, int uOfs, byte[] scalar, int scalarOfs);
        /// <summary>
        /// Multiplication of the base with a scalar 
        /// </summary>
        /// <param name="res"></param>
        /// <param name="resOfs"></param>
        /// <param name="scalar"></param>
        /// <param name="scalarOfs"></param>
        /// <returns></returns>
        int ScalarMultiplicationBase(byte[] res, int resOfs, byte[] scalar, int scalarOfs);
        /// <summary>
        /// Create the public key for a given private key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyOfs"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyOfs"></param>
        /// <returns></returns>
        int CreatePublicKeyFromPrivateKey(byte[] publicKey, int publicKeyOfs, byte[] privateKey, int privateKeyOfs);
        /// <summary>
        /// Create a new pair of keys
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="publicKeyOfs"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyOfs"></param>
        /// <returns></returns>
        int CreateKeyPair(byte[] publicKey, int publicKeyOfs, byte[] privateKey, int privateKeyOfs);

        /// <summary>
        /// create a new pair of keys
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        int CreateKeyPair(out byte[] publicKey, out byte[] privateKey);
    }
}
