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
    /// XSalsa20
    /// </summary>
    public interface IXSalsa20
    {
        /// <summary>
        /// HSalsa20
        /// Calucalate a 32 Byte MAC from input(16 byte), an encryptionkey (32 byte) and a constant (32 byte)
        /// used for subkey calculation in XSalsa
        /// </summary>
        /// <param name="macOut">resulting MAC: 32 byte</param>
        /// <param name="macOutOfs"></param>
        /// <param name="inp">16 Byte Input to be encoded</param>
        /// <param name="inpOfs"></param>
        /// <param name="key">encryption key 32byte</param>
        /// <param name="keyOfs"></param>
        /// <param name="c">constant, if null then SALSA_CONSTANT will be used</param>
        /// <param name="cOfs"></param>
        void HSalsa20(byte[] macOut, int macOutOfs, byte[] inp, int inpOfs, byte[] key, int keyOfs, byte[] c, int cOfs);
        /// <summary>
        /// XSalsa20: 
        ///  first 16 byte of nonce are used to generate subkey (HSalsa), last 8 byte are used as nonce for Salsa20XorIC
        /// </summary>
        /// <param name="destData">output with rawDataLen bytes</param>
        /// <param name="destOfs"></param>
        /// <param name="rawData">input data</param>
        /// <param name="rawDataOfs">offset</param>
        /// <param name="rawDataLen">input len</param>
        /// <param name="nonce">24 byte nonce</param>
        /// <param name="nonceOfs"></param>
        /// <param name="key">shared key</param>
        /// <param name="keyOfs"></param>
        /// <param name="ic">8 byte </param>
        /// <param name="icOfs"></param>
        void XSalsa20XorIC(byte[] destData, int destOfs, byte[] rawData, int rawDataOfs, int rawDataLen, byte[] nonce, int nonceOfs, byte[] key, int keyOfs, byte[] ic, int icOfs);

        /// <summary>
        /// XSalsa20
        /// </summary>
        /// <param name="destData"></param>
        /// <param name="destOfs"></param>
        /// <param name="len"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
        void XSalsa20(byte[] destData, int destOfs, int len, byte[] nonce, int nonceOfs, byte[] key, int keyOfs);
        /// <summary>
        /// Salsa20
        /// </summary>
        /// <param name="destData"></param>
        /// <param name="destOfs"></param>
        /// <param name="len"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
        void Salsa20(byte[] destData, int destOfs, int len, byte[] nonce, int nonceOfs, byte[] key, int keyOfs);        
        /// <summary>
        /// Salsa20XorIC
        /// </summary>
        /// <param name="destData"></param>
        /// <param name="destOfs"></param>
        /// <param name="rawData"></param>
        /// <param name="rawDataOfs"></param>
        /// <param name="rawDataLen"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="key">subkey</param>
        /// <param name="keyOfs"></param>
        /// <param name="ic"></param>
        /// <param name="icOfs"></param>
        void Salsa20XorIC(byte[] destData, int destOfs, byte[] rawData, int rawDataOfs, int rawDataLen, byte[] nonce, int nonceOfs, byte[] key, int keyOfs, byte[] ic, int icOfs);
    }
}
                                                   