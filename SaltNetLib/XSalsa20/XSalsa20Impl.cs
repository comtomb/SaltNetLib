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
using TomB.Util;
using System;
using System.Collections.Generic;
using System.Text;

namespace TomB.SaltNet.Salsa20
{

    /// <summary>
    /// simple Implementation of Salsa20,XSalsa20,HSalsa20
    /// for details see the reference implementation
    /// </summary>
    internal class XSalsa20Impl : AbstractSalsaCore, IXSalsa20
    {
        public XSalsa20Impl()
        {

        }
        /// <summary>
        /// <see cref="IXSalsa20.HSalsa20(byte[], int, byte[], int, byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="macOut"></param>
        /// <param name="macOutOfs"></param>
        /// <param name="inp"></param>
        /// <param name="inpOfs"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
        /// <param name="c"></param>
        /// <param name="cOfs"></param>
        public void HSalsa20(byte[] macOut, int macOutOfs, byte[] inp, int inpOfs, byte[] key, int keyOfs, byte[] c, int cOfs)
        {
            var x = new uint[16];
            SalsaRounds(x, 0, null, 0, inp, inpOfs, key, keyOfs, c, cOfs);

            ByteUtil.PutU32LE(macOut, macOutOfs + 0, x[0]);
            ByteUtil.PutU32LE(macOut, macOutOfs + 4, x[5]);
            ByteUtil.PutU32LE(macOut, macOutOfs + 8, x[10]);
            ByteUtil.PutU32LE(macOut, macOutOfs + 12, x[15]);
            ByteUtil.PutU32LE(macOut, macOutOfs + 16, x[6]);
            ByteUtil.PutU32LE(macOut, macOutOfs + 20, x[7]);
            ByteUtil.PutU32LE(macOut, macOutOfs + 24, x[8]);
            ByteUtil.PutU32LE(macOut, macOutOfs + 28, x[9]);
        }
        /// <summary>
        /// Core of Salsa20: Do the salsa rounds and get the result back
        /// </summary>
        /// <param name="block"></param>
        /// <param name="blockOfs"></param>
        /// <param name="inv"></param>
        /// <param name="invOfs"></param>
        /// <param name="k"></param>
        /// <param name="kOfs"></param>
        /// <param name="c"></param>
        /// <param name="cOfs"></param>
        private void CoreSalsa20(byte[] block, int blockOfs, byte[] inv, int invOfs, byte[] k, int kOfs, byte[] c, int cOfs)
        {
            var x = new uint[16];
            var j = new uint[16];
            SalsaRounds(x, 0, j, 0, inv, invOfs, k, kOfs, c, cOfs);
            unchecked
            {
                for (int i = 0; i < 16; i++)
                    ByteUtil.PutU32LE(block, blockOfs + i * 4, x[i] + j[i]);
            }
        }
        /// <summary>
        /// <see cref="IXSalsa20.XSalsa20XorIC(byte[], int, byte[], int, int, byte[], int, byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="destData"></param>
        /// <param name="destOfs"></param>
        /// <param name="rawData"></param>
        /// <param name="rawDataOfs"></param>
        /// <param name="rawDataLen"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
        /// <param name="ic"></param>
        /// <param name="icOfs"></param>
        public void XSalsa20XorIC(byte[] destData, int destOfs, byte[] rawData, int rawDataOfs, int rawDataLen, byte[] nonce, int nonceOfs, byte[] key, int keyOfs, byte[] ic, int icOfs)
        {
            // subkey
            var subkey = new byte[32];
            HSalsa20(subkey, 0, nonce, 0, key, 0, null, 0);
            Salsa20XorIC(destData,destOfs,rawData,rawDataOfs,rawDataLen,nonce,nonceOfs+16,subkey,0,ic,icOfs);        	
        }
        /// <summary>
        /// <see cref="IXSalsa20.Salsa20XorIC(byte[], int, byte[], int, int, byte[], int, byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="destData"></param>
        /// <param name="destOfs"></param>
        /// <param name="rawData"></param>
        /// <param name="rawDataOfs"></param>
        /// <param name="rawDataLen"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
        /// <param name="ic"></param>
        /// <param name="icOfs"></param>
        public void Salsa20XorIC(byte[] destData, int destOfs, byte[] rawData, int rawDataOfs, int rawDataLen, byte[] nonce, int nonceOfs, byte[] key, int keyOfs, byte[] ic, int icOfs)
        {
        	
            var inp = new byte[16];
            for (int i = 0; i < 8; i++)
                inp[i] = nonce[nonceOfs + i];
            if (ic != null)
            {
                for (int i = 0; i < 8; i++)
                    inp[8 + i] = ic[icOfs + (7 - i)];
                // untested, currently no use case
                throw new NotImplementedException();
            }

            var block = new byte[64];

            while (rawDataLen >= 64)
            {
                CoreSalsa20(block, 0, inp, 0, key, keyOfs, SALSA_CONSTANT, 0);
                for (int i = 0; i < 64; i++)
                    destData[destOfs + i] = (byte)(rawData[rawDataOfs + i] ^ block[i]);
                int u = 1;
                for (int i = 8; i < 16; i++)
                {
                    u += inp[i] & 0xff;
                    inp[i] = (byte)(u&0xff);
                    u >>= 8;
                }
                rawDataLen -= 64;
                rawDataOfs += 64;
                destOfs += 64;
            }
            if (rawDataLen > 0)
            {
                CoreSalsa20(block, 0, inp, 0, key, keyOfs, SALSA_CONSTANT, 0);

                for (int i = 0; i < rawDataLen; i++)
                    destData[destOfs + i] = (byte)(rawData[rawDataOfs + i] ^ block[i]);
            }

        }

        /// <summary>
        /// <see cref="IXSalsa20.XSalsa20(byte[], int, int, byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="destData"></param>
        /// <param name="destOfs"></param>
        /// <param name="len"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
		public void XSalsa20(byte[] destData, int destOfs, int len, byte[] nonce, int nonceOfs, byte[] key, int keyOfs)
		{
            // subkey
            var subkey = new byte[32];
            HSalsa20(subkey, 0, nonce, 0, key, 0, null, 0);
            Salsa20(destData,destOfs,len,nonce,nonceOfs+16,subkey,0);			
		}

        /// <summary>
        /// <see cref="IXSalsa20.Salsa20(byte[], int, int, byte[], int, byte[], int)"/>
        /// </summary>
        /// <param name="destData"></param>
        /// <param name="destOfs"></param>
        /// <param name="len"></param>
        /// <param name="nonce"></param>
        /// <param name="nonceOfs"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
        public void Salsa20(byte[] destData, int destOfs, int len, byte[] nonce, int nonceOfs, byte[] key, int keyOfs)
        {
            var inp = new byte[16];
            for (int i = 0; i < 8; i++)
                inp[i] = nonce[nonceOfs + i];
            for (int i = 0; i < 8; i++)
            	inp[8 + i] = 0;


            while (len >= 64)
            {
                CoreSalsa20(destData, destOfs, inp, 0, key, keyOfs, SALSA_CONSTANT, 0);
                int u = 1;
                for (int i = 8; i < 16; i++)
                {
                    u += inp[i] & 0xff;
                    inp[i] = (byte)(u&0xff);
                    u >>= 8;
                }
                len -= 64;
                destOfs += 64;
            }
            if (len > 0)
            {
            	var block=new byte[64];
                CoreSalsa20(block, 0, inp, 0, key, keyOfs, SALSA_CONSTANT, 0);
                for(int i=0;i<len;i++)
                	destData[destOfs+i]=block[i];
            }
        }

    }
}
