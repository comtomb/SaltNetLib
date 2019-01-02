using TomB.ByteUtilNetLib;
using TomB.SaltNet;
using TomB.SaltNet.Curve25519;
using TomB.SaltNetLib.Curve25519;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace SaltNetLibTest
{

    public class TestCurve25519_Field526
    {
        private readonly ITestOutputHelper output;

        public TestCurve25519_Field526(ITestOutputHelper output)
        {
            this.output = output;
        }
        [Fact]
        public void TestBaseMul2()
        {
            new Curve25519Test().TestMul2(output, new Curve25519Field2526());
        }
        [Fact]
        public void TestBaseMul3()
        {
            new Curve25519Test().TestMul3(output, new Curve25519Field2526());
        }
        [Fact]
        public void TestRFC7748_1()
        {
            new Curve25519Test().TestRFC7748_1(output, new Curve25519Field2526());
        }
        [Fact]
        public void TestRFC7748_2()
        {
            new Curve25519Test().TestRFC7748_2(output, new Curve25519Field2526());
        }
        [Fact]
        public void TestRFC7748_3_longloop()
        {
            new Curve25519Test().TestRFC7748_3(output, new Curve25519Field2526(), 1000000);
        }
        [Fact]
        public void TestRFC7748_3_shortloop()
        {
            new Curve25519Test().TestRFC7748_3(output, new Curve25519Field2526(), 10000);
        }
        [Fact]
        public void TestRFC7748_4()
        {
            new Curve25519Test().TestRFC7748_4(output, new Curve25519Field2526());
        }
        [Fact]
        public void TestReduce()
        {
            //var curveBI=new Curve25519BigInt();
            //curveBI.Validation(Console.Out,1000);
            var curveF = new Curve25519Field2526();

            BigInteger p = Field25519_2526.curve25519p.ToBigInt();
            for (int i = -19; i < 2; i++)
            {
                BigInteger v = p + i;
                BigInteger vMod = BigInteger.Remainder(v, p);
                var fv = new Field25519_2526(v);

                var fvMod = Field25519_2526.Reduce(fv);

                output.WriteLine(v.ToString("X") + " " + vMod.ToString("X") + " " + fvMod.ToBigInt().ToString("X"));
                Assert.True(fv.ToBigInt() == v);
                Assert.True(fvMod.ToBigInt() == vMod);
            }




        }

    }

}
