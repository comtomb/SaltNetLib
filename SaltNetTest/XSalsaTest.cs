﻿/*
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
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using TomB.SaltNet.Salsa20;

namespace SaltNetLibTest
{
    public class XSalsaTest
    {
        [Theory]
        [InlineData("short","1A0C466F5D75E4D8AD6765D5F519DBC82B7C343B37F88500EC5E64005393", 
                            "B30D4A402975CF746C0FF4BEC24D1E04EB4BB598FEA846B5", 
                            "5DEE3FF82D919C86167B2E84876A42B99A4B15126FFE54AB2124BD2ECE16FB29", 
                            "4F36C210174417696B191A5552B2F3419CF36411049F0C894945AC0A3682592B", 
                            "8DAC2A6BD29D7D424AE235A1B3373E574D9C429D2E197ACCFF48A80D35937EE15B373536368F2215ADFD23C49AC381B3A096240C7EB5AD1D29D3152BA805")]
        [InlineData("multi", "1A0C466F5D75E4D8AD6765D5F519DBC82B7C343B37F88500EC5E64005393B30D4A402975CF746C0F", 
                             "F4BEC24D1E04EB4BB598FEA846B56A21864682FE10E4841A", 
                             "B8529596CDA15477BF7222FCC20748C5B2D2FEC1A56795A9E432F8B6CA468451", 
                             "894B3F2E667847834C9E24AC826C304A3C5D391BBB2456DE1D45A71280A81EAF", 
                             "ECF9DFEB58461AA61A7FD6B460C71884ECF46A986396CCB7A968809C1BEC03E0E535A59BDA904"+
                             "1D54C635D1D4F62E52DB180A375F2115E4890A74BFBCEA7A1C4631FC2B46CE68CEB")]
        [InlineData("long",  "1A0C466F5D75E4D8AD6765D5F519DBC82B7C343B37F88500EC5E64005393B30D4A402975CF74" +
                             "6C0FF4BEC24D1E04EB4BB598FEA846B56A21864682FE10E4841AB4578BB4EF66F8B7102446793638" +
                             "E1E773194BBB940AC694D607EE88F16DFF1039A799C779365B4E9F4698216EF1EB4E659A8BF798C9" +
                             "86A991F6DDE87770C5A225363F8F9F1A6E3CBDFC1C4D72A426E51CA02256E208777020EF36835873" +
                             "D72E80F5FC38B15BAE4B2C4E399CAD3837ECD0F8CBD64E6FC01DBECF6EAFE3EBE34A24EDCC7DA8ED" +
                             "33C0F2D72993CEDBC2E8B849B360A801E01134DF79E2EDFE67416BEF77BF6BB943E2C40AE476452D" +
                             "4EE30C85F79A3782A2230DBB49C97451D3F36FE827DF64027CFE06D09C9D1C69CC069095D66707CD" +
                             "09E84C53B2B0707A6D7336F0075D056E7E0909F99367E60406A3EF4238DE7A6CECA2DE3F921150CC" +
                             "8D8B6329672C626E002216CD5D0D39A201484C0FC12E428EF8C903657EC6DB6DB93C6B0703BD9DDA" +
                             "41804115C7AD0EDE683C3D4AC4400A5F49D4309D28FCF03A47A91321A2329E44AA72CE41EC2CC64B" +
                             "BB25FD428890A978320CBE2F8C00B1449007CE1E99ED3C369DF99F5272C9721C0DE5E103FFADB1B6" +
                             "FF9BEE96736FB7AAC089B1E55EA7B1CDE8C7A48FF156056899A121A71EAE44E255181EFDFEA6C22E" +
                             "41F591E8188CBE6533141A380822C5A99586FCD14D10",
                             "8B1245CE904689B4CE4204764EFBC41C4F0CE3BB730A930B", 
                             "F825852F8571CA9ED20C241F8C93727C3D4B9A17BFD25B098DC2A1ED930EC873", 
                             "807F85EE9CE9BA71D6D3964DF1B03129CED9EE5B9CC963960198FEB370F6E3AA",
                             "656DB483105F804A75825A8F937036FD3A8B82D1EE911E1037272794CF1CECD7A5625AB143" +
                             "421E32FC4D4781C766BC7733474C0D2362D107FA02401D0D5A783B578CFA059633808894AE0946A6" +
                             "EC5A33EFBDE1D541DF2ED2DEC6DD5A8D1C45E59423145ACF7AE32D656B747D790C1A69AB5CF5B57D" +
                             "D7CBDD20C6709E2A7B60985DFB4336F8F924144B6E7D4EB0BF8930146FE996229BC3DD1E8AF9A3B9" +
                             "834654C70426DC940632EC2D0A414C57764E3D31BDA5FFA6D590112A1FCE4F32077ACC037FFFD63D" +
                             "7D94CEB123C7E7A6F41CE7AFC2A4C52FFF3110458F88692553ED0D4C17B02F5AD41B3D0DBB7FBDCB" +
                             "094C93F49989D65561AE5CCC0837A7F4479F11066394A0BB16C1BAB244A5ECC57B10C6AC4CDFDC9D" +
                             "5C866BC132511F38AD4F3BA4F7485951D658C24977C9FF11CA690470D9F28A0D6411182A346C36F0" +
                             "7D64442DDBFB90B3FE5870F438A0B1E84CF7843CED1DA93F8DBE35727E3D270796B4A5A520C759BD" +
                             "1A92F135C73E383B9FEC0CC0B6EDF1CA3169BE6DE67CA45D131DC050C933FBFF9EAFF5E8C9DE1F91" +
                             "7AE0308902D45584915E56D8D7866A5E159D5A8A72DD496D02D83D70ED43F1A9BF879F3B15EAFE6D" +
                             "7AAFF70633915127EB1B29332783C29FFA776F2E85C383C9C3691FA32A8DCB3E23A86A9D56399705" +
                             "591BFE78BC97E601D67C2A2F1444EB092287E05225A559A44992CBFA02B128C3574523D55ADDD058" +
                             "41D232E362C1F6AD998C058740C5C2")]
        public void TestXSalsa20(String desc,String rawStr,string nonceStr,string keyStr,string expSubKeyStr,string expSalsaStr)
        {
            var xsalsa = new XSalsa20Impl();
            byte[] subKey = new byte[32];

            var nonce = ByteUtil.HexToByteArray(nonceStr);
            var key = ByteUtil.HexToByteArray(keyStr);
            var raw = ByteUtil.HexToByteArray(rawStr);

            xsalsa.HSalsa20(subKey, 0, nonce, 0, key, 0, null, 0);
            Assert.Equal(subKey, ByteUtil.HexToByteArray(expSubKeyStr));

            byte[] extRaw = new byte[raw.Length + 32];
            Array.Copy(raw, 0, extRaw, 32, raw.Length);
            byte[] salsa = new byte[raw.Length + 32];

            xsalsa.Salsa20XorIC(salsa, 0, extRaw, 0, extRaw.Length, nonce, 16, subKey, 0, null, 0);
            Assert.Equal(salsa, ByteUtil.HexToByteArray(expSalsaStr));

        }

    }
}
