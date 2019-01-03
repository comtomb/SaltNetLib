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
