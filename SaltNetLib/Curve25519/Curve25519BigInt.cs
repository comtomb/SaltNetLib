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
using System.Diagnostics;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using System.Runtime.CompilerServices;
using TomB.ByteUtilNetLib;

namespace TomB.SaltNet.Curve25519
{
    /// <summary>
    /// Curve25519 based on BigInteger Arithmetic
    /// 
    /// The performance of this is a nightmare, but it's good to understand what's going on in a 
    /// Scalarmultiplication in a Curve25519
    /// </summary>
    internal class Curve25519BigInt : AbstractCurve25519
    {
        /// <summary>
        /// modulo
        /// </summary>
        private static readonly BigInteger curve25519pBI = (new BigInteger(2) << 254) - new BigInteger(19);
        /// <summary>
        /// montgomery A
        /// </summary>
        private static readonly BigInteger montgomeryA = new BigInteger(486662);
        /// <summary>
        /// a24 
        /// </summary>
        private static readonly BigInteger a24 = (montgomeryA + 2) / 4;

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
        public override int ScalarMultiplicationRaw(byte[] res, int resOfs, byte[] u, int uOfs, byte[] k, int kOfs)
        {
            // we do a montgomery ladder 				
            var x1 = BigIntHelper.FromBytesLE(u, uOfs, 32);
            int swap = 0;

            // array with x0,z0, r0x,r0z,r1x,r1z
            BigInteger[] arr = new BigInteger[] { x1, BigInteger.One, BigInteger.One, BigInteger.Zero, x1, BigInteger.One };

            for (int i = 254; i >= 0; i--)
            {
                // get the i-th bit of the LE scalar
                int ki = (k[kOfs + (i >> 3)] >> (i & 7)) & 1;

                swap ^= ki;
                CSwapArr(swap, arr);
                swap = ki;

                DifferentialDoubleAndAdd(arr);

            }
            CSwapArr(swap, arr);

            var r0zinv = BigIntHelper.ModInverse(arr[3], curve25519pBI);
            var r0x = BigInteger.Multiply(arr[2], r0zinv);
            BigInteger.DivRem(r0x, curve25519pBI, out r0x);
            BigIntHelper.ToBytesLE(res, resOfs, r0x, 32);
            return 0;
        }
        private void CSwapArr(int swap,BigInteger[] field)
        {
            // TODO migrate to time constant bit operation
            if( swap==1)
            { 
                var h1 = field[2];
                field[2] = field[4];
                field[4] = h1;
                var h2 = field[3];
                field[3] = field[5];
                field[5] = h2;
            }
            else
            {

            }
        }

        /**
         * Differential double and add
         * 
         * see https://hyperelliptic.org/EFD/g1p/data/montgom/xz/ladder/mladd-1987-m
         * 
         * source 1987 Montgomery "Speeding the Pollard and elliptic curve methods of factorization", page 261, fifth and sixth displays, plus common-subexpression elimination, plus assumption Z1=1
         * assume Z1 = 1
         * parameter a24
         * assume 4 * a24 = a+2
         * 
         * compute A = X2+Z2
         * compute AA = A^2
         * compute B = X2-Z2
         * compute BB = B^2
         * compute E = AA-BB
         * compute C = X3+Z3
         * compute D = X3-Z3
         * compute DA = D A
         * compute CB = C B
         * compute X5 = (DA+CB)^2
         * compute Z5 = X1(DA-CB)^2
         * compute X4 = AA BB
         * compute Z4 = E(BB + a24 E)
         * 
         *  result: arr[2]=x coordinate 2*P, arr[3]=z coordinate 2*P, arr[4] x coordinate P+Q, arr[5] z coordinate P+Q
         * 
         * @param arr [0]:  	x coordinate P-Q , [1]:z coordinate P-Q, [2]: x coordinate P, [3]: z coordinate P, [4]: x coordinate Q, [5]: x coordinate Q
         * 
         * 
         */
        private void DifferentialDoubleAndAdd(BigInteger[] arr)

        {

            var hA = BigInteger.Add(arr[2], arr[3]);    // X2+Z2
            var hAA = BigInteger.Multiply(hA, hA);      //  square
            var hB = BigInteger.Subtract(arr[2], arr[3]);  // X2-Z2
            var hBB = BigInteger.Multiply(hB, hB);      //  square
            var hE = BigInteger.Subtract(hAA, hBB);
            var hC = BigInteger.Add(arr[4], arr[5]);        // X3+Z3
            var hD = BigInteger.Subtract(arr[4], arr[5]);   // X3-Z3
            var hDA = BigInteger.Multiply(hD, hA);
            var hCB = BigInteger.Multiply(hC, hB);

            // x2+x3
            var x5 = BigInteger.Add(hDA, hCB);
            x5 = BigInteger.Multiply(x5, x5); // square
            var z5 = BigInteger.Subtract(hDA, hCB);
            z5 = BigInteger.Multiply(z5, z5); // square
            z5 = BigInteger.Multiply(z5, arr[0]); // z5*x1

            // 2*x2
            var x4 = BigInteger.Multiply(hAA, hBB);
            var z4 = BigInteger.Multiply(a24, hE);
            z4 = BigInteger.Add(z4, hBB);
            z4 = BigInteger.Multiply(z4, hE);

            arr[2] = BigInteger.Remainder(x4, curve25519pBI);
            arr[3] = BigInteger.Remainder(z4, curve25519pBI);
            arr[4] = BigInteger.Remainder(x5, curve25519pBI);
            arr[5] = BigInteger.Remainder(z5, curve25519pBI);

        }
    }
    /// <summary>
    /// a helper class for BigIntegers
    /// </summary>
    internal class BigIntHelper
    {
        /// <summary>
        /// BigInteger from a Little Endian HEX-String
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static BigInteger FromStringLE(string s)
        {
            byte[] arr = ByteUtil.HexToByteArray(s);
            return new BigInteger(arr);
        }
        /// <summary>
        /// BigInteger to a ByteArray
        /// </summary>
        /// <param name="v"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        public static byte[] ToBytesLEtoArray(BigInteger v, int len)
        {
            byte[] h = v.ToByteArray();
            if (h.Length == len)
                return h;
            // TODO align to len?
            throw new NotImplementedException();
        }
        /// <summary>
        /// BigInteger from Little Endian byte array
        /// </summary>
        /// <param name="src"></param>
        /// <param name="srcOfs"></param>
        /// <param name="srcLen"></param>
        /// <returns></returns>
        public static BigInteger FromBytesLE(byte[] src, int srcOfs, int srcLen)
        {
            if (src[srcOfs + srcLen - 1] > 127)
            {
                throw new NotImplementedException();
            }
            else
            {
                byte[] h = new byte[srcLen];
                Array.Copy(src, srcOfs, h, 0, srcLen);
                return new BigInteger(h);
            }
        }
        /// <summary>
        /// BigInteger to Little Endian  byte[] array
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="destOfs"></param>
        /// <param name="v"></param>
        /// <param name="len"></param>
        public static void ToBytesLE(byte[] dest, int destOfs, BigInteger v, int len)
        {
            byte[] h = v.ToByteArray();
            if (h.Length > len)
                throw new ArgumentException();
            h.CopyTo(dest, destOfs);
            for (int i = h.Length; i < len; i++)
                dest[destOfs + i] = 0;
        }
        /// <summary>
        /// modular inverse
        /// </summary>
        /// <param name="a"></param>
        /// <param name="n"></param>
        /// <returns></returns>
        public static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            return BigInteger.ModPow(a, n - 2, n);
        }
        /// <summary>
        /// test if a bit is set
        /// </summary>
        /// <param name="v"></param>
        /// <param name="bit"></param>
        /// <returns></returns>
        public static bool TestBit(BigInteger v, int bit)
        {
            return ((v >> bit) & BigInteger.One) == BigInteger.One;
        }
    }
}
