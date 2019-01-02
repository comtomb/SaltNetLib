using TomB.ByteUtilNetLib;
using TomB.SaltNet;
using TomB.SaltNet.Curve25519;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace SaltNetLibTest
{
    public class Curve25519Test
    {
        /**
         * u of base point 
         */
        public static readonly byte[] uBase = new byte[] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        /**
         * base *2 --> 14847277145635483483963372537557091634710985132825781088887140890597596352251
         */
        public static readonly byte[] uBaseM2 = ByteUtil.HexToByteArray("FB4E68DD9C46AE5C5C0B351EED5C3F8F1471157D680C75D9B7F17318D542D320");

        /**
         * base *3 --> 12697861248284385512127539163427099897745340918349830473877503196793995869202
         */
        public static readonly byte[] uBaseM3 = ByteUtil.HexToByteArray("123C71FBAF030AC059081C62674E82F864BA1BC2914D5345E6AB576D1ABC121C");

        public void TestMul2(ITestOutputHelper output, ICurve25519 curve)
        {
            byte[] scalar2 = new byte[32];
            scalar2[0] = 2;
            byte[] res = new byte[32];
            curve.ScalarMultiplicationRaw(res, 0, uBase, 0, scalar2, 0);
            output.WriteLine(ByteUtil.BytesToHexString(res) + " " + ByteUtil.BytesToHexString(uBaseM2));
            Assert.Equal(uBaseM2, res);
        }
        public void TestMul3(ITestOutputHelper output, ICurve25519 curve)
        {
            byte[] scalar3 = new byte[32];
            scalar3[0] = 3;
            byte[] res = new byte[32];
            curve.ScalarMultiplicationRaw(res, 0, uBase, 0, scalar3, 0);
            Assert.Equal(uBaseM3, res);
        }
        public void TestRFC7748_1(ITestOutputHelper output, ICurve25519 curve)
        {
            byte[] scalarBY = ByteUtil.HexToByteArray("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
            byte[] uBY = ByteUtil.HexToByteArray("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

            BigInteger exp = BigIntHelper.FromStringLE("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");


            // scalar multiplication
            byte[] res = new byte[32];
            curve.ScalarMultiplication(res, 0, uBY, 0, scalarBY, 0);

            Assert.Equal(BigIntHelper.ToBytesLEtoArray(exp, 32), res);

        }

        public void TestRFC7748_2(ITestOutputHelper output, ICurve25519 curve)
        {
            byte[] scalarBY = ByteUtil.HexToByteArray("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
            byte[] uBY = ByteUtil.HexToByteArray("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
            BigInteger exp = BigIntHelper.FromStringLE("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

            // scalar multiplication
            byte[] res = new byte[32];
            curve.ScalarMultiplication(res, 0, uBY, 0, scalarBY, 0);

            Assert.Equal(BigIntHelper.ToBytesLEtoArray(exp, 32), res);

        }
        public void TestRFC7748_3(ITestOutputHelper output, ICurve25519 curve, int maxLoops)
        {
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
            output.WriteLine("performing " + maxLoops + " iterations");
            for (int i = 1; i <= maxLoops; i++)
            {
                byte[] h = new byte[32];
                curve.ScalarMultiplication(h, 0, u, 0, k, 0);
                u = k;
                k = h;
                if ((i % 100) == 0)
                {
                    DateTime tn = DateTime.Now;
                    TimeSpan elapsed = TimeSpan.FromTicks(tn.Ticks - t0.Ticks);
                    long rate = (long)((i * 1000) / elapsed.TotalMilliseconds);
                    output.WriteLine(i + " " + ByteUtil.BytesToHexString(k) + "-> elapsed: " + elapsed + " rate: " + rate + "/s");
                }
                if (i == 1)
                {
                    c++;
                    Assert.Equal(k1, k);
                }
                if (i == 1000)
                {
                    c++;
                    Assert.Equal(k1000, k);
                }
                if (i == 10000)
                {
                    Assert.Equal(k10000, k);
                }
                if (i == 1000000)
                {
                    c++;
                    Assert.Equal(k1000000, k);
                }

            }


        }
        public void TestRFC7748_4(ITestOutputHelper output, ICurve25519 curve)
        {
            byte[] alicePrivate = ByteUtil.HexToByteArray("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            byte[] alicePublic = ByteUtil.HexToByteArray("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
            byte[] bobPrivate = ByteUtil.HexToByteArray("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            byte[] bobPublic = ByteUtil.HexToByteArray("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

            byte[] expectedShared = ByteUtil.HexToByteArray("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");


            byte[] bobShared = new byte[32];
            curve.ScalarMultiplication(bobShared, 0, alicePublic, 0, bobPrivate, 0);
            Assert.Equal(expectedShared, bobShared);

            byte[] aliceShared = new byte[32];
            curve.ScalarMultiplication(aliceShared, 0, bobPublic, 0, alicePrivate, 0);
            Assert.Equal(expectedShared, aliceShared);

            // and of course as A=B and B=C ==> A=C
            Assert.Equal(aliceShared, bobShared);
        }
    }

    public class TestCurve25519_BigInt
    {
        private readonly ITestOutputHelper output;

        public TestCurve25519_BigInt(ITestOutputHelper output)
        {
            this.output = output;
        }
        [Fact]
        public void TestBaseMul2()
        {
            new Curve25519Test().TestMul2(output, new Curve25519BigInt());
        }
        [Fact]
        public void TestBaseMul3()
        {
            new Curve25519Test().TestMul3(output, new Curve25519BigInt());
        }
        [Fact]
        public void TestRFC7748_1()
        {
            new Curve25519Test().TestRFC7748_1(output, new Curve25519BigInt());
        }
        [Fact]
        public void TestRFC7748_2()
        {
            new Curve25519Test().TestRFC7748_2(output, new Curve25519BigInt());
        }
        [Fact]
        public void TestRFC7748_3_longloop()
        {
            new Curve25519Test().TestRFC7748_3(output, new Curve25519BigInt(), 1000000);
        }
        [Fact]
        public void TestRFC7748_4()
        {
            new Curve25519Test().TestRFC7748_4(output, new Curve25519BigInt());
        }

    }

}
