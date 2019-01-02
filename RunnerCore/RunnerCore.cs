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
using TomB.SaltNet;
using TomB.SaltNet.Poly1305;
using TomB.SaltNetLib.Curve25519;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Text;

namespace Runner
{
    public class Runner
    {
        public static void Main(string[] args)
        {
            var cryptoBox = BoxCurve25519XSalsa20Poly1305Factory.CreateInstance();

            byte[] aliceSecretKey;
            byte[] alicePublicKey;
            byte[] bobSecretKey;
            byte[] bobPublicKey;

            // create key pairs for Alice and Bob
            cryptoBox.CreateKeyPair(out alicePublicKey, out aliceSecretKey);
            cryptoBox.CreateKeyPair(out bobPublicKey, out bobSecretKey);


            // create a shared key to send from Alice to Bob
            var sharedKeyAlice2Bob = cryptoBox.CreateSharedKey(bobPublicKey, aliceSecretKey);
            // a message
            string sendMessage = "the quick brown fox jumped over the lazy dog";
            Console.WriteLine("Alice want's to send: " + sendMessage);

            // convert to bytes
            var sendMessagBytes = Encoding.ASCII.GetBytes(sendMessage);

            // a 24 byte nonce
            var nonce = cryptoBox.RandomNonce();
            var encrypted = cryptoBox.EncryptSymmetric(sharedKeyAlice2Bob, nonce, sendMessagBytes);

            Console.WriteLine("encrypted message (16 byte Poly1305 MAC, followed by " + sendMessage.Length + " byte XSALSA20 encrypted text and 24 byte nonce");
            for (int i = 0; i < encrypted.Length; i++)
                Console.Write(encrypted[i].ToString("X2"));
            for (int i = 0; i < nonce.Length; i++)
                Console.Write(nonce[i].ToString("X2"));
            Console.WriteLine();


            // now let Bob calculate the shared key
            var sharedKeyBobFromAlice = cryptoBox.CreateSharedKey(alicePublicKey, bobSecretKey); // of course equal to sharedKeyAlice2Bob...
            var decrypted = cryptoBox.DecryptSymmetric(sharedKeyBobFromAlice, nonce, encrypted);
            string receivedMessage = Encoding.ASCII.GetString(decrypted);
            Console.WriteLine("bob received: " + receivedMessage);
            

            
        }
    }
}
