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
using System.Diagnostics;
using System.Numerics;
using TomB.Util;
using TomB.SaltNet;
using TomB.SaltNet.Curve25519;

namespace TomB.SaltNetLib.Curve25519
{

    /// <summary>
    /// Curve25519 based on a a Field of int[]
    /// this is the default implementation
    /// </summary>
    internal class Curve25519Field2526 : AbstractCurve25519
    {
        /// <summary>
        /// constant
        /// </summary>
        private const int a24int = (486662 + 2) / 4;

        /// <summary>
        /// constructor
        /// </summary>
        public Curve25519Field2526()
        {
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
        public override int ScalarMultiplicationRaw(byte[] res, int resOfs, byte[] u, int uOfs, byte[] k, int kOfs)
        {
            // no parameter check: usually this is called by one of the "high level" methods

            // perform a montgomery ladder 				
            var x1 = new Field25519_2526(u, uOfs);

            int swap = 0;

            // array with x0,z0, r0x,r0z,r1x,r1z
            var arr = new Field25519_2526[] { x1, Field25519_2526.One, Field25519_2526.One, Field25519_2526.Zero, x1, Field25519_2526.One };

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

            var r0zinv = Field25519_2526.ModInverse(arr[3]);
            var r0x = Field25519_2526.Multiply(arr[2], r0zinv);
            r0x.ToBytesLE(res, resOfs);
            return 0;
        }
        /// <summary>
        /// conditional swap
        /// </summary>
        /// <param name="swap"></param>
        /// <param name="field"></param>
        private void CSwapArr(int swap, Field25519_2526[] field)
        {
            // TODO migrate to time constant bit operation
            if (swap == 1)
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
         * assume 4 a24 = a+2
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
        private void DifferentialDoubleAndAdd(Field25519_2526[] arr)
        {
            var hA = Field25519_2526.Add(arr[2], arr[3]);    // X2+Z2
            var hAA = Field25519_2526.Square(hA);
            var hB = Field25519_2526.Subtract(arr[2], arr[3]);  // X2-Z2
            var hBB = Field25519_2526.Square(hB);
            var hE = Field25519_2526.Subtract(hAA, hBB);
            var hC = Field25519_2526.Add(arr[4], arr[5]);        // X3+Z3
            var hD = Field25519_2526.Subtract(arr[4], arr[5]);   // X3-Z3
            var hDA = Field25519_2526.Multiply(hD, hA);
            var hCB = Field25519_2526.Multiply(hC, hB);

            // x2+x3
            var x5 = Field25519_2526.Add(hDA, hCB);
            x5 = Field25519_2526.Square(x5);
            var z5 = Field25519_2526.Subtract(hDA, hCB);
            z5 = Field25519_2526.Square(z5);
            z5 = Field25519_2526.Multiply(z5, arr[0]); // z5*x1

            // 2*x2
            var x4 = Field25519_2526.Multiply(hAA, hBB);
            var z4 = Field25519_2526.MultiplyScalar(hE, a24int);
            z4 = Field25519_2526.Add(z4, hBB);
            z4 = Field25519_2526.Multiply(z4, hE);

            arr[2] = x4;
            arr[3] = z4;
            arr[4] = x5;
            arr[5] = z5;

        }

    }


    /// <summary>
    /// modulo arithmetic in ^255-19
    /// base is an array of 10 integers (the field)
    /// in each element 25 or 26 bits are used (FIELD_LEN)
    /// </summary>
    internal class Field25519_2526
    {
        // length of the field elements
        private const int FIELD_LEN_0 = 26;
        private const int FIELD_LEN_1 = 25;
        private const int FIELD_LEN_2 = 26;
        private const int FIELD_LEN_3 = 25;
        private const int FIELD_LEN_4 = 26;
        private const int FIELD_LEN_5 = 25;
        private const int FIELD_LEN_6 = 26;
        private const int FIELD_LEN_7 = 25;
        private const int FIELD_LEN_8 = 26;
        private const int FIELD_LEN_9 = 25;

        // mask for each element
        private const int FIELD_MASK_0 = (1 << FIELD_LEN_0) - 1;
        private const int FIELD_MASK_1 = (1 << FIELD_LEN_1) - 1;
        private const int FIELD_MASK_2 = (1 << FIELD_LEN_2) - 1;
        private const int FIELD_MASK_3 = (1 << FIELD_LEN_3) - 1;
        private const int FIELD_MASK_4 = (1 << FIELD_LEN_4) - 1;
        private const int FIELD_MASK_5 = (1 << FIELD_LEN_5) - 1;
        private const int FIELD_MASK_6 = (1 << FIELD_LEN_6) - 1;
        private const int FIELD_MASK_7 = (1 << FIELD_LEN_7) - 1;
        private const int FIELD_MASK_8 = (1 << FIELD_LEN_8) - 1;
        private const int FIELD_MASK_9 = (1 << FIELD_LEN_9) - 1;



        // array for all lens
        private static int[] FIELD_LENS = new int[] {FIELD_LEN_0,
                                                   FIELD_LEN_1,
                                                   FIELD_LEN_2,
                                                   FIELD_LEN_3,
                                                   FIELD_LEN_4,
                                                   FIELD_LEN_5,
                                                   FIELD_LEN_6,
                                                   FIELD_LEN_7,
                                                   FIELD_LEN_8,
                                                   FIELD_LEN_9
                                                  };
        // array for all masks
        private static int[] FIELD_MASKS = new int[] {FIELD_MASK_0,
                                                    FIELD_MASK_1,
                                                    FIELD_MASK_2,
                                                    FIELD_MASK_3,
                                                    FIELD_MASK_4,
                                                    FIELD_MASK_5,
                                                    FIELD_MASK_6,
                                                    FIELD_MASK_7,
                                                    FIELD_MASK_8,
                                                    FIELD_MASK_9
                                                  };

        /// <summary>
        /// number of Fields
        /// </summary>
        private const int Fields = 10;


        /// <summary>
        /// modulo for curve: 2^255-19
        /// (LE representation)
        /// </summary>
        public static readonly Field25519_2526 curve25519p = new Field25519_2526(ByteUtil.HexToByteArray("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F"), 0);
        /// <summary>
        /// 1
        /// </summary>
        public static readonly Field25519_2526 One = new Field25519_2526(1);
        /// <summary>
        /// 0
        /// </summary>
        public static readonly Field25519_2526 Zero = new Field25519_2526(0);

        /// <summary>
        /// the actual field
        /// </summary>
        private int[] field = new int[Fields];


        #region Constructors & Conversions		
        public Field25519_2526()
        {
        }
        /// <summary>
        /// copy constructor
        /// </summary>
        /// <param name="other"></param>
        public Field25519_2526(Field25519_2526 other)
        {
            for (int i = 0; i < Fields; i++)
                field[i] = other.field[i];
        }

        /// <summary>
        /// constructor from BigInteger
        /// </summary>
        /// <param name="v"></param>
        public Field25519_2526(BigInteger v)
        {
            int shift = 0;
            for (int i = 0; i < Fields; i++)
            {
                field[i] = (int)((v >> shift) & new BigInteger(FIELD_MASKS[i]));
                shift += FIELD_LENS[i];
            }
        }
        /// <summary>
        /// constructor for LE byte[]
        /// </summary>
        /// <param name="v"></param>
        /// <param name="ofs"></param>
        public Field25519_2526(byte[] v, int ofs)
        {
            // a lot of bit magic to map from input to 25/26 fields
            field[0] = (int)v[ofs + 0];
            field[0] |= ((int)v[ofs + 1]) << 8;
            field[0] |= ((int)v[ofs + 2]) << 16;
            field[0] |= ((((int)v[ofs + 3])) & 3) << 24;

            field[1] = ((((int)v[ofs + 3])) & 0xfc) >> 2;
            field[1] |= ((int)v[ofs + 4]) << 6;
            field[1] |= ((int)v[ofs + 5]) << 14;
            field[1] |= ((((int)v[ofs + 6])) & 7) << 22;

            field[2] = ((((int)v[ofs + 6])) & 0xf8) >> 3;
            field[2] |= ((int)v[ofs + 7]) << 5;
            field[2] |= ((int)v[ofs + 8]) << 13;
            field[2] |= ((((int)v[ofs + 9])) & 0x1f) << 21;

            field[3] = ((((int)v[ofs + 9])) & 0xe0) >> 5;
            field[3] |= ((int)v[ofs + 10]) << 3;
            field[3] |= ((int)v[ofs + 11]) << 11;
            field[3] |= ((((int)v[ofs + 12])) & 0x3f) << 19;

            field[4] = ((((int)v[ofs + 12])) & 0xe0) >> 6;
            field[4] |= ((int)v[ofs + 13]) << 2;
            field[4] |= ((int)v[ofs + 14]) << 10;
            field[4] |= ((int)v[ofs + 15]) << 18;
            field[5] |= ((int)v[ofs + 16]);
            field[5] |= ((int)v[ofs + 17]) << 8;
            field[5] |= ((int)v[ofs + 18]) << 16;
            field[5] |= ((((int)v[ofs + 19])) & 0x1) << 24;

            field[6] = ((((int)v[ofs + 19])) & 0xfe) >> 1;
            field[6] |= ((int)v[ofs + 20]) << 7;
            field[6] |= ((int)v[ofs + 21]) << 15;
            field[6] |= ((((int)v[ofs + 22])) & 0x7) << 23;

            field[7] = ((((int)v[ofs + 22])) & 0xf8) >> 3;
            field[7] |= ((int)v[ofs + 23]) << 5;
            field[7] |= ((int)v[ofs + 24]) << 13;
            field[7] |= ((((int)v[ofs + 25])) & 0xf) << 21;

            field[8] = ((((int)v[ofs + 25])) & 0xf0) >> 4;
            field[8] |= ((int)v[ofs + 26]) << 4;
            field[8] |= ((int)v[ofs + 27]) << 12;
            field[8] |= ((((int)v[ofs + 28])) & 0x3f) << 20;

            field[9] = ((((int)v[ofs + 28])) & 0xc0) >> 6;
            field[9] |= ((int)v[ofs + 29]) << 2;
            field[9] |= ((int)v[ofs + 30]) << 10;
            field[9] |= ((int)v[ofs + 31]) << 18;
        }
        /// <summary>
        /// constructor for int
        /// </summary>
        /// <param name="v"></param>
        public Field25519_2526(int v)
        {
            field[0] = v & FIELD_MASK_0;
            field[1] = (v >> FIELD_LEN_0) & FIELD_MASK_1;
        }
        /// <summary>
        /// Field to BigInteger
        /// </summary>
        /// <returns></returns>
        public BigInteger ToBigInt()
        {
            BigInteger s = BigInteger.Zero;
            int shift = 0;
            for (int i = 0; i < Fields; i++)
            {
                s = s + (new BigInteger(field[i]) << shift);
                shift += FIELD_LENS[i];
            }
            return s;
        }
        /// <summary>
        /// Field to BigInteger, result &lt;p
        /// </summary>
        /// <returns></returns>
        public BigInteger ToBigIntMod()
        {
            return BigInteger.Remainder(ToBigInt(), curve25519p.ToBigInt());
        }
        /// <summary>
        /// debug only
        /// </summary>
        /// <returns></returns>
        public string Dump()
        {
            String s = "";
            for (int i = 0; i < Fields; i++)
                s = s + field[i].ToString("x8") + " ";
            return s;
        }
        /// <summary>
        /// convert to a byte[] 
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="ofs"></param>
        public void ToBytesLE(byte[] dest, int ofs)
        {
            // make sure we have a proper (reduced) format
            ReduceInner(this);
            // and some bit magic
            dest[ofs + 0] = (byte)(field[0] >> 0 & 0xff);
            dest[ofs + 1] = (byte)(field[0] >> 8 & 0xff);
            dest[ofs + 2] = (byte)(field[0] >> 16 & 0xff);
            dest[ofs + 3] = (byte)((field[0] >> 24 & 0x3) | ((field[1] & 0x3f) << 2));  // 2|6
            dest[ofs + 4] = (byte)(field[1] >> 6 & 0xff);
            dest[ofs + 5] = (byte)(field[1] >> 14 & 0xff);
            dest[ofs + 6] = (byte)((field[1] >> 22 & 0x7) | ((field[2] & 0x1f) << 3));  // 3|5
            dest[ofs + 7] = (byte)(field[2] >> 5 & 0xff); ;
            dest[ofs + 8] = (byte)(field[2] >> 13 & 0xff);
            dest[ofs + 9] = (byte)((field[2] >> 21 & 0x1f) | ((field[3] & 0x7) << 5));  // 5|3
            dest[ofs + 10] = (byte)(field[3] >> 3 & 0xff);
            dest[ofs + 11] = (byte)(field[3] >> 11 & 0xff);
            dest[ofs + 12] = (byte)((field[3] >> 19 & 0x3f) | ((field[4] & 0x3) << 6)); // 6|2
            dest[ofs + 13] = (byte)(field[4] >> 2 & 0xff);
            dest[ofs + 14] = (byte)(field[4] >> 10 & 0xff);
            dest[ofs + 15] = (byte)(field[4] >> 18 & 0xff);
            dest[ofs + 16] = (byte)(field[5] >> 0 & 0xff);
            dest[ofs + 17] = (byte)(field[5] >> 8 & 0xff);
            dest[ofs + 18] = (byte)(field[5] >> 16 & 0xff);
            dest[ofs + 19] = (byte)((field[5] >> 24 & 0x1) | ((field[6] & 0x7f) << 1)); // 1|7
            dest[ofs + 20] = (byte)(field[6] >> 7 & 0xff);
            dest[ofs + 21] = (byte)(field[6] >> 15 & 0xff);
            dest[ofs + 22] = (byte)((field[6] >> 23 & 0x7) | ((field[7] & 0x1f) << 3)); // 3|5
            dest[ofs + 23] = (byte)(field[7] >> 5 & 0xff);
            dest[ofs + 24] = (byte)(field[7] >> 13 & 0xff);
            dest[ofs + 25] = (byte)((field[7] >> 21 & 0xf) | ((field[8] & 0xf) << 4));  // 4|4
            dest[ofs + 26] = (byte)(field[8] >> 4 & 0xff);
            dest[ofs + 27] = (byte)(field[8] >> 12 & 0xff);
            dest[ofs + 28] = (byte)((field[8] >> 20 & 0x3f) | ((field[9] & 0x3) << 6)); // 6|2
            dest[ofs + 29] = (byte)(field[9] >> 2 & 0xff); ;
            dest[ofs + 30] = (byte)(field[9] >> 10 & 0xff);
            dest[ofs + 31] = (byte)(field[9] >> 18 & 0xff);


        }
        #endregion

        #region arithmetic implementation
        /// <summary>
        /// add without carry. 
        /// </summary>
        /// <param name="res"></param>
        /// <param name="a"></param>
        /// <param name="b"></param>
        private static void AddNoCarry(Field25519_2526 res, Field25519_2526 a, Field25519_2526 b)
        {
            for (int i = 0; i < Fields; i++)
            {
                int s = a.field[i] + b.field[i];
                res.field[i] = s;
            }
        }
        /// <summary>
        /// subtract without carry
        /// </summary>
        /// <param name="res"></param>
        /// <param name="a"></param>
        /// <param name="b"></param>
        private static void SubtractNoCarry(Field25519_2526 res, Field25519_2526 a, Field25519_2526 b)
        {
            for (int i = 0; i < Fields; i++)
            {
                int d = a.field[i] + curve25519p.field[i] - b.field[i];
                res.field[i] = d;
            }
        }

        /// <summary>
        /// Reduce the field
        ///			
        /// claim: floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q. proof can be seen in fe_reduce() in the reference implemenentation
        /// </summary>
        /// <param name="h"></param>

        // 	field[i]<1<<FIELD_LENS[i]
        // 	field < 2^255 - 19
        private static void ReduceInner(Field25519_2526 h)
        {
            // 19*2^(-25)*h9 + 2^(-1) ==> 2^(-25) * (19*h9 + 2^24) 						
            int q = (19 * h.field[9] + (1 << 24)) >> 25;
            q = (h.field[0] + q) >> 26;
            q = (h.field[1] + q) >> 25;
            q = (h.field[2] + q) >> 26;
            q = (h.field[3] + q) >> 25;
            q = (h.field[4] + q) >> 26;
            q = (h.field[5] + q) >> 25;
            q = (h.field[6] + q) >> 26;
            q = (h.field[7] + q) >> 25;
            q = (h.field[8] + q) >> 26;
            q = (h.field[9] + q) >> 25;



            int carry = 19 * q;
            for (int i = 0; i < Fields; i++)
            {
                int s = h.field[i] + carry;
                carry = s >> FIELD_LENS[i];
                h.field[i] = s & FIELD_MASKS[i];
            }
            // we need to ignore carry: q==1 ==> this is the 2^(-255) of the formula, otherwise carry=0 

            Debug.Assert((q == 0 && carry == 0) || (q == 1 && carry == 1));

        }
        /// <summary>
        /// compare to Fields withou performin a normalizeation/reduction
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns>&gt;0 if a&gt;b, &lt;0 if a &gt;b</returns>
        private static int CompareToNoNormalize(Field25519_2526 a, Field25519_2526 b)
        {
            for (int i = Fields - 1; i >= 0; i--)
            {
                int d = a.field[i] - b.field[i];
                if (d > 0)
                    return 1 + i;
                if (d < 0)
                    return -1 - i;
            }
            return 0;
        }
        /// <summary>
        /// Multiply: res=a*b
        /// 
        /// schoolbook multilplication
        /// 
        /// </summary>
        /// <param name="res"></param>
        /// <param name="a"></param>
        /// <param name="b"></param>
        private static void Multiply(Field25519_2526 res, Field25519_2526 a, Field25519_2526 b)
        {

            int a0 = a.field[0];
            int a1 = a.field[1];
            int a2 = a.field[2];
            int a3 = a.field[3];
            int a4 = a.field[4];
            int a5 = a.field[5];
            int a6 = a.field[6];
            int a7 = a.field[7];
            int a8 = a.field[8];
            int a9 = a.field[9];

            int b0 = b.field[0];
            int b1 = b.field[1];
            int b2 = b.field[2];
            int b3 = b.field[3];
            int b4 = b.field[4];
            int b5 = b.field[5];
            int b6 = b.field[6];
            int b7 = b.field[7];
            int b8 = b.field[8];
            int b9 = b.field[9];

            long a0b0 = (long)a0 * (long)b0;
            long a0b1 = (long)a0 * (long)b1;
            long a0b2 = (long)a0 * (long)b2;
            long a0b3 = (long)a0 * (long)b3;
            long a0b4 = (long)a0 * (long)b4;
            long a0b5 = (long)a0 * (long)b5;
            long a0b6 = (long)a0 * (long)b6;
            long a0b7 = (long)a0 * (long)b7;
            long a0b8 = (long)a0 * (long)b8;
            long a0b9 = (long)a0 * (long)b9;
            long a1b0 = (long)a1 * (long)b0;
            long a1b1 = (long)a1 * (long)b1;
            long a1b2 = (long)a1 * (long)b2;
            long a1b3 = (long)a1 * (long)b3;
            long a1b4 = (long)a1 * (long)b4;
            long a1b5 = (long)a1 * (long)b5;
            long a1b6 = (long)a1 * (long)b6;
            long a1b7 = (long)a1 * (long)b7;
            long a1b8 = (long)a1 * (long)b8;
            long a1b9 = (long)a1 * (long)b9;
            long a2b0 = (long)a2 * (long)b0;
            long a2b1 = (long)a2 * (long)b1;
            long a2b2 = (long)a2 * (long)b2;
            long a2b3 = (long)a2 * (long)b3;
            long a2b4 = (long)a2 * (long)b4;
            long a2b5 = (long)a2 * (long)b5;
            long a2b6 = (long)a2 * (long)b6;
            long a2b7 = (long)a2 * (long)b7;
            long a2b8 = (long)a2 * (long)b8;
            long a2b9 = (long)a2 * (long)b9;
            long a3b0 = (long)a3 * (long)b0;
            long a3b1 = (long)a3 * (long)b1;
            long a3b2 = (long)a3 * (long)b2;
            long a3b3 = (long)a3 * (long)b3;
            long a3b4 = (long)a3 * (long)b4;
            long a3b5 = (long)a3 * (long)b5;
            long a3b6 = (long)a3 * (long)b6;
            long a3b7 = (long)a3 * (long)b7;
            long a3b8 = (long)a3 * (long)b8;
            long a3b9 = (long)a3 * (long)b9;
            long a4b0 = (long)a4 * (long)b0;
            long a4b1 = (long)a4 * (long)b1;
            long a4b2 = (long)a4 * (long)b2;
            long a4b3 = (long)a4 * (long)b3;
            long a4b4 = (long)a4 * (long)b4;
            long a4b5 = (long)a4 * (long)b5;
            long a4b6 = (long)a4 * (long)b6;
            long a4b7 = (long)a4 * (long)b7;
            long a4b8 = (long)a4 * (long)b8;
            long a4b9 = (long)a4 * (long)b9;
            long a5b0 = (long)a5 * (long)b0;
            long a5b1 = (long)a5 * (long)b1;
            long a5b2 = (long)a5 * (long)b2;
            long a5b3 = (long)a5 * (long)b3;
            long a5b4 = (long)a5 * (long)b4;
            long a5b5 = (long)a5 * (long)b5;
            long a5b6 = (long)a5 * (long)b6;
            long a5b7 = (long)a5 * (long)b7;
            long a5b8 = (long)a5 * (long)b8;
            long a5b9 = (long)a5 * (long)b9;
            long a6b0 = (long)a6 * (long)b0;
            long a6b1 = (long)a6 * (long)b1;
            long a6b2 = (long)a6 * (long)b2;
            long a6b3 = (long)a6 * (long)b3;
            long a6b4 = (long)a6 * (long)b4;
            long a6b5 = (long)a6 * (long)b5;
            long a6b6 = (long)a6 * (long)b6;
            long a6b7 = (long)a6 * (long)b7;
            long a6b8 = (long)a6 * (long)b8;
            long a6b9 = (long)a6 * (long)b9;
            long a7b0 = (long)a7 * (long)b0;
            long a7b1 = (long)a7 * (long)b1;
            long a7b2 = (long)a7 * (long)b2;
            long a7b3 = (long)a7 * (long)b3;
            long a7b4 = (long)a7 * (long)b4;
            long a7b5 = (long)a7 * (long)b5;
            long a7b6 = (long)a7 * (long)b6;
            long a7b7 = (long)a7 * (long)b7;
            long a7b8 = (long)a7 * (long)b8;
            long a7b9 = (long)a7 * (long)b9;
            long a8b0 = (long)a8 * (long)b0;
            long a8b1 = (long)a8 * (long)b1;
            long a8b2 = (long)a8 * (long)b2;
            long a8b3 = (long)a8 * (long)b3;
            long a8b4 = (long)a8 * (long)b4;
            long a8b5 = (long)a8 * (long)b5;
            long a8b6 = (long)a8 * (long)b6;
            long a8b7 = (long)a8 * (long)b7;
            long a8b8 = (long)a8 * (long)b8;
            long a8b9 = (long)a8 * (long)b9;
            long a9b0 = (long)a9 * (long)b0;
            long a9b1 = (long)a9 * (long)b1;
            long a9b2 = (long)a9 * (long)b2;
            long a9b3 = (long)a9 * (long)b3;
            long a9b4 = (long)a9 * (long)b4;
            long a9b5 = (long)a9 * (long)b5;
            long a9b6 = (long)a9 * (long)b6;
            long a9b7 = (long)a9 * (long)b7;
            long a9b8 = (long)a9 * (long)b8;
            long a9b9 = (long)a9 * (long)b9;


            // calculate coeefficients. 
            long r0 = a0b0 +
                    19 * (2 * a1b9 + a2b8 + 2 * a3b7 + a4b6 + 2 * a5b5 + a6b4 + 2 * a7b3 + a8b2 + 2 * a9b1);
            long r1 = a0b1 + a1b0 +
                    19 * (a2b9 + a3b8 + a4b7 + a5b6 + a6b5 + a7b4 + a8b3 + a9b2);
            long r2 = a0b2 + 2 * a1b1 + a2b0 +
                    19 * (2 * a3b9 + a4b8 + 2 * a5b7 + a6b6 + 2 * a7b5 + a8b4 + 2 * a9b3);
            long r3 = a0b3 + a1b2 + a2b1 + a3b0 +
                    19 * (a4b9 + a5b8 + a6b7 + a7b6 + a8b5 + a9b4);
            long r4 = a0b4 + 2 * a1b3 + a2b2 + 2 * a3b1 + a4b0 +
                    19 * (2 * a5b9 + a6b8 + 2 * a7b7 + a8b6 + 2 * a9b5);
            long r5 = a0b5 + a1b4 + a2b3 + a3b2 + a4b1 + a5b0 +
                    19 * (a6b9 + a7b8 + a8b7 + a9b6);
            long r6 = a0b6 + 2 * a1b5 + a2b4 + 2 * a3b3 + a4b2 + 2 * a5b1 + a6b0 +
                    19 * (2 * a7b9 + a8b8 + 2 * a9b7);
            long r7 = a0b7 + a1b6 + a2b5 + a3b4 + a4b3 + a5b2 + a6b1 + a7b0 +
                    19 * (a8b9 + a9b8);
            long r8 = a0b8 + 2 * a1b7 + a2b6 + 2 * a3b5 + a4b4 + 2 * a5b3 + a6b2 + 2 * a7b1 + a8b0 +
                    38 * a9b9;
            long r9 = a0b9 + a1b8 + a2b7 + a3b6 + a4b5 + a5b4 + a6b3 + a7b2 + a8b1 + a9b0;


            // carry from r9 --> r0
            long c9 = r9 >> FIELD_LEN_9;
            r9 &= FIELD_MASK_9;
            // reduce all coefficients to fit into 32bit
            long s0 = r0 + c9 * 19;
            long c0 = s0 >> FIELD_LEN_0;
            r0 = s0 & FIELD_MASK_0;

            long s1 = r1 + c0;
            long c1 = s1 >> FIELD_LEN_1;
            r1 = s1 & FIELD_MASK_1;

            long s2 = r2 + c1;
            long c2 = s2 >> FIELD_LEN_2;
            r2 = s2 & FIELD_MASK_2;

            long s3 = r3 + c2;
            long c3 = s3 >> FIELD_LEN_3;
            r3 = s3 & FIELD_MASK_3;

            long s4 = r4 + c3;
            long c4 = s4 >> FIELD_LEN_4;
            r4 = s4 & FIELD_MASK_4;

            long s5 = r5 + c4;
            long c5 = s5 >> FIELD_LEN_5;
            r5 = s5 & FIELD_MASK_5;

            long s6 = r6 + c5;
            long c6 = s6 >> FIELD_LEN_6;
            r6 = s6 & FIELD_MASK_6;


            long s7 = r7 + c6;
            long c7 = s7 >> FIELD_LEN_7;
            r7 = s7 & FIELD_MASK_7;

            long s8 = r8 + c7;
            long c8 = s8 >> FIELD_LEN_8;
            r8 = s8 & FIELD_MASK_8;

            long s9 = r9 + c8;
            c9 = s9 >> FIELD_LEN_9;
            r9 = s9 & FIELD_MASK_9;

            // warp from r9 to r0
            s0 = r0 + c9 * 19;
            c0 = s0 >> FIELD_LEN_0;
            r0 = s0 & FIELD_MASK_0;

            s1 = r1 + c0;
            c1 = s1 >> FIELD_LEN_1;
            r1 = s1 & FIELD_MASK_1;

            r2 += c1;
            // we should be save now, stop normalization: r2 might exceed 1<<26, but it fits into 32 bit. 
            Debug.Assert(r2 >> 32 == 0L);


            // convert back
            res.field[0] = (int)r0;
            res.field[1] = (int)r1;
            res.field[2] = (int)r2;
            res.field[3] = (int)r3;
            res.field[4] = (int)r4;
            res.field[5] = (int)r5;
            res.field[6] = (int)r6;
            res.field[7] = (int)r7;
            res.field[8] = (int)r8;
            res.field[9] = (int)r9;



        }
        /// <summary>
        /// Square: res=a*a
        /// Schoolbook multiplication, but with reduced number of coeeficients"/>
        /// </summary>
        /// <param name="res"></param>
        /// <param name="a"></param>
        private static void Square(Field25519_2526 res, Field25519_2526 a)
        {
            int a0 = a.field[0];
            int a0_2 = 2 * a0;
            int a1 = a.field[1];
            int a1_2 = 2 * a1;
            int a1_4 = 4 * a1;
            int a2 = a.field[2];
            int a2_2 = 2 * a2;
            int a3 = a.field[3];
            int a3_2 = 2 * a3;
            int a3_4 = 4 * a3;
            int a4 = a.field[4];
            int a4_2 = 2 * a4;
            int a5 = a.field[5];
            int a5_2 = 2 * a5;
            int a5_4 = 4 * a5;
            int a6 = a.field[6];
            int a6_2 = 2 * a6;
            int a7 = a.field[7];
            int a7_2 = 2 * a7;
            int a7_4 = 4 * a7;
            int a8 = a.field[8];
            int a8_2 = 2 * a8;
            int a9 = a.field[9];


            long a0a0 = (long)a0 * (long)a0;
            long a0a1_2 = (long)a0_2 * (long)a1;
            long a0a2_2 = (long)a0_2 * (long)a2;
            long a0a3_2 = (long)a0_2 * (long)a3;
            long a0a4_2 = (long)a0_2 * (long)a4;
            long a0a5_2 = (long)a0_2 * (long)a5;
            long a0a6_2 = (long)a0_2 * (long)a6;
            long a0a7_2 = (long)a0_2 * (long)a7;
            long a0a8_2 = (long)a0_2 * (long)a8;
            long a0a9_2 = (long)a0_2 * (long)a9;
            long a1a1_2 = (long)a1_2 * (long)a1;
            long a1a2_2 = (long)a1_2 * (long)a2;
            long a1a3_4 = (long)a1_4 * (long)a3;
            long a1a4_2 = (long)a1_2 * (long)a4;
            long a1a5_4 = (long)a1_4 * (long)a5;
            long a1a6_2 = (long)a1_2 * (long)a6;
            long a1a7_4 = (long)a1_4 * (long)a7;
            long a1a8_2 = (long)a1_2 * (long)a8;
            long a1a9_4 = (long)a1_4 * (long)a9;
            long a2a2 = (long)a2 * (long)a2;
            long a2a3_2 = (long)a2_2 * (long)a3;
            long a2a4_2 = (long)a2_2 * (long)a4;
            long a2a5_2 = (long)a2_2 * (long)a5;
            long a2a6_2 = (long)a2_2 * (long)a6;
            long a2a7_2 = (long)a2_2 * (long)a7;
            long a2a8_2 = (long)a2_2 * (long)a8;
            long a2a9_2 = (long)a2_2 * (long)a9;
            long a3a3_2 = (long)a3_2 * (long)a3;
            long a3a4_2 = (long)a3_2 * (long)a4;
            long a3a5_4 = (long)a3_4 * (long)a5;
            long a3a6_2 = (long)a3_2 * (long)a6;
            long a3a7_4 = (long)a3_4 * (long)a7;
            long a3a8_2 = (long)a3_2 * (long)a8;
            long a3a9_4 = (long)a3_4 * (long)a9;
            long a4a4 = (long)a4 * (long)a4;
            long a4a5_2 = (long)a4_2 * (long)a5;
            long a4a6_2 = (long)a4_2 * (long)a6;
            long a4a7_2 = (long)a4_2 * (long)a7;
            long a4a8_2 = (long)a4_2 * (long)a8;
            long a4a9_2 = (long)a4_2 * (long)a9;
            long a5a5_2 = (long)a5_2 * (long)a5;
            long a5a6_2 = (long)a5_2 * (long)a6;
            long a5a7_4 = (long)a5_4 * (long)a7;
            long a5a8_2 = (long)a5_2 * (long)a8;
            long a5a9_4 = (long)a5_4 * (long)a9;
            long a6a6 = (long)a6 * (long)a6;
            long a6a7_2 = (long)a6_2 * (long)a7;
            long a6a8_2 = (long)a6_2 * (long)a8;
            long a6a9_2 = (long)a6_2 * (long)a9;
            long a7a7_2 = (long)a7_2 * (long)a7;
            long a7a8_2 = (long)a7_2 * (long)a8;
            long a7a9_4 = (long)a7_4 * (long)a9;
            long a8a8 = (long)a8 * (long)a8;
            long a8a9_2 = (long)a8_2 * (long)a9;
            long a9a9 = (long)a9 * (long)a9;


            // calculate coeefficients. 
            long r0 = a0a0 +
                    19 * (a1a9_4 + a2a8_2 + a3a7_4 + a4a6_2 + a5a5_2);
            long r1 = a0a1_2 +
                    19 * (a2a9_2 + a3a8_2 + a4a7_2 + a5a6_2);
            long r2 = a0a2_2 + a1a1_2 +
                    19 * (a3a9_4 + a4a8_2 + a5a7_4 + a6a6);
            long r3 = a0a3_2 + a1a2_2 +
                    19 * (a4a9_2 + a5a8_2 + a6a7_2);
            long r4 = a0a4_2 + a1a3_4 + a2a2 +
                    19 * (a5a9_4 + a6a8_2 + a7a7_2);
            long r5 = a0a5_2 + a1a4_2 + a2a3_2 +
                    19 * (a6a9_2 + a7a8_2);
            long r6 = a0a6_2 + a1a5_4 + a2a4_2 + a3a3_2 +
                    19 * (a7a9_4 + a8a8);
            long r7 = a0a7_2 + a1a6_2 + a2a5_2 + a3a4_2 +
                    19 * (a8a9_2);
            long r8 = a0a8_2 + a1a7_4 + a2a6_2 + a3a5_4 + a4a4 +
                    38 * a9a9;
            long r9 = a0a9_2 + a1a8_2 + a2a7_2 + a3a6_2 + a4a5_2;


            // carry from r9 --> r0
            long c9 = r9 >> FIELD_LEN_9;
            r9 &= FIELD_MASK_9;
            // reduce all coefficients to fit into 32bit
            long s0 = r0 + c9 * 19;
            long c0 = s0 >> FIELD_LEN_0;
            r0 = s0 & FIELD_MASK_0;

            long s1 = r1 + c0;
            long c1 = s1 >> FIELD_LEN_1;
            r1 = s1 & FIELD_MASK_1;

            long s2 = r2 + c1;
            long c2 = s2 >> FIELD_LEN_2;
            r2 = s2 & FIELD_MASK_2;

            long s3 = r3 + c2;
            long c3 = s3 >> FIELD_LEN_3;
            r3 = s3 & FIELD_MASK_3;

            long s4 = r4 + c3;
            long c4 = s4 >> FIELD_LEN_4;
            r4 = s4 & FIELD_MASK_4;

            long s5 = r5 + c4;
            long c5 = s5 >> FIELD_LEN_5;
            r5 = s5 & FIELD_MASK_5;

            long s6 = r6 + c5;
            long c6 = s6 >> FIELD_LEN_6;
            r6 = s6 & FIELD_MASK_6;


            long s7 = r7 + c6;
            long c7 = s7 >> FIELD_LEN_7;
            r7 = s7 & FIELD_MASK_7;

            long s8 = r8 + c7;
            long c8 = s8 >> FIELD_LEN_8;
            r8 = s8 & FIELD_MASK_8;

            long s9 = r9 + c8;
            c9 = s9 >> FIELD_LEN_9;
            r9 = s9 & FIELD_MASK_9;

            // wrap from r9 to r0
            s0 = r0 + c9 * 19;
            c0 = s0 >> FIELD_LEN_0;
            r0 = s0 & FIELD_MASK_0;

            s1 = r1 + c0;
            c1 = s1 >> FIELD_LEN_1;
            r1 = s1 & FIELD_MASK_1;

            r2 += c1;
            // we should be save now, stop normalization: r2 might exceed 1<<26, but it fits into 32 bit. 
            Debug.Assert(r2 >> 32 == 0L);


            // convert back
            res.field[0] = (int)r0;
            res.field[1] = (int)r1;
            res.field[2] = (int)r2;
            res.field[3] = (int)r3;
            res.field[4] = (int)r4;
            res.field[5] = (int)r5;
            res.field[6] = (int)r6;
            res.field[7] = (int)r7;
            res.field[8] = (int)r8;
            res.field[9] = (int)r9;



        }
        /// <summary>
        /// multiplication with a scalar
        /// </summary>
        /// <param name="res"></param>
        /// <param name="a"></param>
        /// <param name="b"></param>
        private static void MultiplyScalar(Field25519_2526 res, Field25519_2526 a, int b)
        {
            // schoolbook multiplication
            long bl = (long)b;
            long a0b = a.field[0] * bl;
            long a1b = a.field[1] * bl;
            long a2b = a.field[2] * bl;
            long a3b = a.field[3] * bl;
            long a4b = a.field[4] * bl;
            long a5b = a.field[5] * bl;
            long a6b = a.field[6] * bl;
            long a7b = a.field[7] * bl;
            long a8b = a.field[8] * bl;
            long a9b = a.field[9] * bl;


            long s;
            long c;
            s = a0b;
            res.field[0] = (int)(s & FIELD_MASK_0);
            c = s >> FIELD_LEN_0;
            s = a1b + c;
            res.field[1] = (int)(s & FIELD_MASK_1);
            c = s >> FIELD_LEN_1;
            s = a2b + c;
            res.field[2] = (int)(s & FIELD_MASK_2);
            c = s >> FIELD_LEN_2;
            s = a3b + c;
            res.field[3] = (int)(s & FIELD_MASK_3);
            c = s >> FIELD_LEN_3;
            s = a4b + c;
            res.field[4] = (int)(s & FIELD_MASK_4);
            c = s >> FIELD_LEN_4;
            s = a5b + c;
            res.field[5] = (int)(s & FIELD_MASK_5);
            c = s >> FIELD_LEN_5;
            s = a6b + c;
            res.field[6] = (int)(s & FIELD_MASK_6);
            c = s >> FIELD_LEN_6;
            s = a7b + c;
            res.field[7] = (int)(s & FIELD_MASK_7);
            c = s >> FIELD_LEN_7;
            s = a8b + c;
            res.field[8] = (int)(s & FIELD_MASK_8);
            c = s >> FIELD_LEN_8;
            s = a9b + c;
            res.field[9] = (int)(s & FIELD_MASK_9);
            c = s >> FIELD_LEN_9;

            Debug.Assert(c < (1 << FIELD_LEN_0));
            res.field[0] += (int)c * 19;

        }
        #endregion

        #region public arithmetic
        /// <summary>
        /// Multilplication with a scalar
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static Field25519_2526 MultiplyScalar(Field25519_2526 a, int b)
        {

            var res = new Field25519_2526();
            MultiplyScalar(res, a, b);
            return res;
        }
        /// <summary>
        /// a*b
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static Field25519_2526 Multiply(Field25519_2526 a, Field25519_2526 b)
        {
            var res = new Field25519_2526();
            Multiply(res, a, b);
            return res;
        }
        /// <summary>
        /// a*a
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        public static Field25519_2526 Square(Field25519_2526 a)
        {
            var res = new Field25519_2526();
            Square(res, a);
            return res;
        }
        /// <summary>
        /// a+b
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static Field25519_2526 Add(Field25519_2526 a, Field25519_2526 b)
        {
            var res = new Field25519_2526();
            AddNoCarry(res, a, b);
            return res;
        }
        /// <summary>
        /// a-b (without reduction/normalization --> single field elements may be &lt;0
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static Field25519_2526 Subtract(Field25519_2526 a, Field25519_2526 b)
        {

            var res = new Field25519_2526();
            SubtractNoCarry(res, a, b);

            return res;
        }
        /// <summary>
        /// mod inverse (chinese remainder theorem)
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        public static Field25519_2526 ModInverse(Field25519_2526 a)
        {
            // this is a sequence of Square-and-multiply 
            // basically we compute a^(p-2)
            var resX = new Field25519_2526(1);
            for (int i = 0; i < 250; i++)	// 250*1
            {
                Field25519_2526.Square(resX, resX);
                Field25519_2526.Multiply(resX, resX, a);
            }

            Field25519_2526.Square(resX, resX); // 0
            Field25519_2526.Square(resX, resX); // 1
            Field25519_2526.Multiply(resX, resX, a);
            Field25519_2526.Square(resX, resX); // 0
            Field25519_2526.Square(resX, resX); // 1
            Field25519_2526.Multiply(resX, resX, a);
            Field25519_2526.Square(resX, resX); // 1
            Field25519_2526.Multiply(resX, resX, a);

            return resX;
        }
        #endregion

        #region Helper
        /// <summary>
        /// copy from another
        /// </summary>
        /// <param name="other"></param>
        private void CopyFrom(Field25519_2526 other)
        {
            for (int i = 0; i < Fields; i++)
                field[i] = other.field[i];
        }
        /// <summary>
        /// to string
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return ToBigInt().ToString();
        }
        /// <summary>
        /// reduction
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        public static Field25519_2526 Reduce(Field25519_2526 a)
        {
            var f = new Field25519_2526(a);
            ReduceInner(f);
            return f;
        }
        #endregion
    }

}
