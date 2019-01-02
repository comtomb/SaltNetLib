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
using System.Runtime.CompilerServices;
using System.Text;
using TomB.ByteUtilNetLib;

namespace TomB.SaltNet.Salsa20
{
    /// <summary>
    /// Abstract Base class for Salsa20 
    /// </summary>
    internal class AbstractSalsaCore
    {
        // constant "expa", "nd 3", "2-by", "te k" [LE format]
        public static readonly byte[] SALSA_CONSTANT = new byte[] { 0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b };


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint Rotate(uint v, int c)
        {
            return (v << c) | (v >> (32 - c));
        }
        /// <summary>
        /// core of Salsa
        /// perform the salsa rounds
        /// </summary>
        /// <param name="x">buffer for 16 uint (=64 byte) output</param>
        /// <param name="xOfs">start of buffer</param>
        /// <param name="xRawOut"></param>
        /// <param name="xRawOutOfs"></param>
        /// <param name="inp">buffer with 16 byte input</param>
        /// <param name="inpOfs">offset</param>
        /// <param name="key">buffer with 32 byte key</param>
        /// <param name="keyOfs"></param>
        /// <param name="c">buffer with 16 byte constant, SALSA_CONSTANT if null</param>
        /// <param name="cOfs"></param>
        protected  void SalsaRounds(uint[] x, int xOfs, uint[] xRawOut, int xRawOutOfs, byte[] inp, int inpOfs, byte[] key, int keyOfs, byte[] c, int cOfs)
        {
            if (c == null)
            {
                c = SALSA_CONSTANT;
                cOfs = 0;
            }
            x[xOfs + 0] = ByteUtil.GetU32LE(c, cOfs + 0);
            x[xOfs + 5] = ByteUtil.GetU32LE(c, cOfs + 4);
            x[xOfs + 10] = ByteUtil.GetU32LE(c, cOfs + 8);
            x[xOfs + 15] = ByteUtil.GetU32LE(c, cOfs + 12);


            x[xOfs + 1] = ByteUtil.GetU32LE(key, keyOfs + 0);
            x[xOfs + 2] = ByteUtil.GetU32LE(key, keyOfs + 4);
            x[xOfs + 3] = ByteUtil.GetU32LE(key, keyOfs + 8);
            x[xOfs + 4] = ByteUtil.GetU32LE(key, keyOfs + 12);
            x[xOfs + 11] = ByteUtil.GetU32LE(key, keyOfs + 16);
            x[xOfs + 12] = ByteUtil.GetU32LE(key, keyOfs + 20);
            x[xOfs + 13] = ByteUtil.GetU32LE(key, keyOfs + 24);
            x[xOfs + 14] = ByteUtil.GetU32LE(key, keyOfs + 28);
            x[xOfs + 6] = ByteUtil.GetU32LE(inp, inpOfs + 0);
            x[xOfs + 7] = ByteUtil.GetU32LE(inp, inpOfs + 4);
            x[xOfs + 8] = ByteUtil.GetU32LE(inp, inpOfs + 8);
            x[xOfs + 9] = ByteUtil.GetU32LE(inp, inpOfs + 12);
                                    
            
            if (xRawOut != null)
                Array.Copy(x, xOfs, xRawOut, xRawOutOfs, 16);
            unchecked
            {
	            for (int i = 0; i < 10; i++)
	            {
		            //column round: QuarterRound(x, 0, 4, 8, 12);	            
					x[4]^=Rotate(x[0] + x[12],7);
					x[8]^=Rotate(x[4] + x[0],9);
					x[12]^=Rotate(x[8] + x[4],13);
					x[0]^=Rotate(x[12] + x[8],18);
		            	            
		            //column round: QuarterRound(x, 5, 9, 13, 1);
					x[9]^=Rotate(x[5] + x[1],7);
					x[13]^=Rotate(x[9] + x[5],9);
					x[1]^=Rotate(x[13] + x[9],13);
					x[5]^=Rotate(x[1] + x[13],18);
		            
		            // column round: QuarterRound(x, 10, 14, 2, 6);
		            x[14]^=Rotate(x[10] + x[6],7);
					x[2]^=Rotate(x[14] + x[10],9);
					x[6]^=Rotate(x[2] + x[14],13);
					x[10]^=Rotate(x[6] + x[2],18);
	
		            // column round: QuarterRound(x, 15, 3, 7, 11);
					x[3]^=Rotate(x[15] + x[11],7);
					x[7]^=Rotate(x[3] + x[15],9);
					x[11]^=Rotate(x[7] + x[3],13);
					x[15]^=Rotate(x[11] + x[7],18);
		            
		            
		            // row round: QuarterRound(x, 0, 1, 2, 3);
		            x[1]^=Rotate(x[0] + x[3],7);
					x[2]^=Rotate(x[1] + x[0],9);
					x[3]^=Rotate(x[2] + x[1],13);
					x[0]^=Rotate(x[3] + x[2],18);
	
		            // row round: QuarterRound(x, 5, 6, 7, 4);
					x[6]^=Rotate(x[5] + x[4],7);
					x[7]^=Rotate(x[6] + x[5],9);
					x[4]^=Rotate(x[7] + x[6],13);
					x[5]^=Rotate(x[4] + x[7],18);
		            
		            // row round: QuarterRound(x, 10, 11, 8, 9);
					x[11]^=Rotate(x[10] + x[9],7);
					x[8]^=Rotate(x[11] + x[10],9);
					x[9]^=Rotate(x[8] + x[11],13);
					x[10]^=Rotate(x[9] + x[8],18);
		            
		            // row round: QuarterRound(x, 15, 12, 13, 14);
					x[12]^=Rotate(x[15] + x[14],7);
					x[13]^=Rotate(x[12] + x[15],9);
					x[14]^=Rotate(x[13] + x[12],13);
					x[15]^=Rotate(x[14] + x[13],18);		            
	            }
            }
        }
    }
}
