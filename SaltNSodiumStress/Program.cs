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
using TomB.SaltNet.Salsa20;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SaltNSodium
{
    internal static class LibSodium
    {
        const string dllName = "libsodium";


		[DllImportAttribute(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_core_hsalsa20")]
        public static extern int crypto_core_hsalsa20(byte[] res, byte[] inp,byte[] k, byte[] c);
        
        
		[DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_stream_salsa20_xor_ic")]
		public static extern int crypto_stream_salsa20_xor_ic(byte[] dest,byte[] msg,UInt64  m,byte[] nonce, UInt64 ic,byte[] key);

        	
		[DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_scalarmult_curve25519_ref10_base")]
        public static extern int crypto_scalarmult_curve25519_ref10_base(byte[] q, byte[] n);
        
		[DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_scalarmult_curve25519_base")]
        public static extern int crypto_scalarmult_curve25519_base(byte[] q, byte[] n);
        

		[DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_scalarmult_curve25519")]
		public static extern int crypto_scalarmult_curve25519(byte[] q, byte[] n, byte[] p);

        
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box_afternm")]
        public static extern int CryptoBoxAfterNm(byte[] c, byte[] m, long mlen, byte[] n, byte[] k);

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box_open_afternm")]
        public static extern int CryptoBoxOpenAfterNm(byte[] m, byte[] c, long clen, byte[] n, byte[] k);

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box_beforenm")]
        public static extern int CryptoBoxBeforeNm(byte[] k, byte[] pk, byte[] sk);

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box")]
        public static extern int crypto_box(byte[] dest, byte[] m, ulong mlen, byte[] n, byte[] pk, byte[] sk );
        

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box_open")]
        public static extern int crypto_box_open(byte[] dest, byte[] c, ulong clen, byte[] n, byte[] pk, byte[] sk );

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_stream_xsalsa20")]
        public static extern int crypto_stream_xsalsa20(byte[] c, ulong clen, byte[] n, byte[] k);
        
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_stream_xsalsa20_xor")]
        public static extern int crypto_stream_xsalsa20_xor(byte[] c, byte[] m, ulong mlen, byte[] n,byte[] k);

        
        
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "crypto_box_keypair")]
        public static extern void CryptoBoxKeypair(byte[] publicKey, byte[] secretKey);

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "randombytes_buf")]
        public static extern void RandomBytesBuf(byte[] buffer, int size);
        


    }
	
	
	class Token
	{
		public byte[] u;
		public byte[] k;
		public byte[] uk;
		
		public byte[] privateKey1;
		public byte[] publicKey1;
		public byte[] privateKey2;
		public byte[] publicKey2;
		public byte[] sharedKey;
		public byte[] nonce;
		public byte[] rawData;
		public byte[] encryptedData;
		public byte[] hsalsa20PrivateKey1;
	}
	class Producer
	{
		ManualResetEvent evtComplete;
		volatile int state;
		int id;
		Random rnd;
		BlockingCollection<Token> queue;
		int loops;
		public Producer(int id,BlockingCollection<Token> queue,int seed,int loops)
		{
			this.id=id;
			this.queue=queue;
			rnd=new Random(seed);
			state=0;
			this.loops=loops;
			evtComplete=new ManualResetEvent(false);
		}
		public void Start()
		{
			var thrd=new Thread( Produce );
            thrd.Name = "Producer_" + id;
            thrd.Priority = ThreadPriority.AboveNormal;
			thrd.Start();
		}
        String DumpArr(byte[] arr)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < arr.Length; i++)
            {
                sb.Append(arr[i].ToString("X2"));
            }
            return sb.ToString();
        }

        private void Produce()
		{
			try
			{
				byte[] u=new byte[32];
				byte[] k=new byte[32];
				rnd.NextBytes(u);
				rnd.NextBytes(k);
				
				for(int i=0;i<loops;i++)
				{
					var token=new Token();

					// scalar multiplication
					//token.u=(byte[])u.Clone();
					//token.k=(byte[])k.Clone();
					//token.uk=new byte[32];

     //               token.k[0] &= 248;
     //               token.k[31] &= 127;
     //               token.k[31] |= 64;
     //               token.u[31] &= 127;

     //               LibSodium.crypto_scalarmult_curve25519(token.uk,token.k,token.u);
					//Array.Copy(token.k, u,0);
					//Array.Copy(token.uk,k,0);
					

					// privateKey1->publicKey1
					token.privateKey1=new byte[32];
					token.publicKey1=new byte[32];
					LibSodium.CryptoBoxKeypair(token.publicKey1,token.privateKey1);
					// privateKey2->publicKey2
					token.privateKey2=new byte[32];
					token.publicKey2=new byte[32];
					LibSodium.CryptoBoxKeypair(token.publicKey2,token.privateKey2);
					
					// shared key
					token.sharedKey=new byte[32];
					LibSodium.CryptoBoxBeforeNm(token.sharedKey,token.publicKey2,token.privateKey1);

                    // HSalsa20
                    token.hsalsa20PrivateKey1 = new byte[32];
                    byte[] hsalsa = new byte[32];
                    LibSodium.crypto_core_hsalsa20(token.hsalsa20PrivateKey1, new byte[16], token.privateKey1, null);

                    // encrypt
                    if( rnd.Next(100)>97)
                        token.rawData = new byte[rnd.Next(2000000, 4000000)];
                    else
                        token.rawData = new byte[rnd.Next(10, 10000)];
                    token.rawData[0]=(byte)(rnd.Next()&0xff);
                    for(int a=1;a<token.rawData.Length;a++)
                    {
                    	token.rawData[a]=(byte)((token.rawData[a-1]+a)&0xff);
                    }
                    //rnd.NextBytes(token.rawData);
                    token.nonce = new byte[24];
                    rnd.NextBytes(token.nonce);
                    var extRaw = new byte[token.rawData.Length + 32];
                    token.rawData.CopyTo(extRaw, 32);
                    var tmpCipher = new byte[extRaw.Length];
                    LibSodium.CryptoBoxAfterNm(tmpCipher, extRaw, extRaw.Length, token.nonce, token.sharedKey);
                    token.encryptedData = new byte[token.rawData.Length + 16];
                    Array.Copy(tmpCipher, 16, token.encryptedData, 0, token.encryptedData.Length);



                    queue.Add(token);
				}
				state=1;
			} catch( Exception e)
			{
				Console.WriteLine(e);
				state=-1;
			}
			evtComplete.Set();			
		}
		public int WaitCompletion()
		{
			evtComplete.WaitOne();
			return state;
		}
	}
	class Consumer
	{
		int id;
		volatile int state=0;
		BlockingCollection<Token> queue;
		ManualResetEvent evtComplete;
		public Consumer(int id, BlockingCollection<Token> queue)
		{
			this.id=id;
			this.queue=queue;
			this.evtComplete=new ManualResetEvent(false);
		}
		public void Start()
		{
			Thread thrd=new Thread( Consume );
            thrd.Name = "Consumer_" + id;
            thrd.Priority = ThreadPriority.BelowNormal;

            thrd.Start();
		}
		private bool ArrayCompare(byte[] a,byte[] b)
		{
            if (a.Length != b.Length)
            	return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i])
            		return false;
            return true;
		}
        private void ArrayCompareThr(byte[] a,byte[] b)
        {
            if (a.Length != b.Length)
                throw new Exception();
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i])
                    throw new Exception();
        }
		private void Consume()
		{
			try
			{
				int c=0;
				DateTime dtS=DateTime.Now;
                var box = BoxCurve25519XSalsa20Poly1305Factory.CreateInstance();

                var curve = box.GetCurve25519();
                var xsalsa = box.GetXSalsa20();
                DateTime t0=DateTime.Now;
                int rateCount=0;
				while( true )
				{
					Token t;
					if( queue.TryTake(out t) )
					{
                        // scalar multiplication
                        //byte[] resUK = new byte[32];
                        //curve.ScalarMultiplication(resUK, 0, t.u, 0, t.k, 0);
                        //if( !ArrayCompare(resUK, t.uk) )
                        //{
                        //	Console.WriteLine( ByteUtil.BytesToHexString(t.u) + "|" + ByteUtil.BytesToHexString(t.k) +"|" + ByteUtil.BytesToHexString(t.uk));
                        //	throw new Exception();
                        //}

                        // public key
                        //byte[] pub1 = new byte[32];
                        //curve.CreatePublicKeyFromPrivateKey(pub1, 0, t.privateKey1, 0);
                        //if(!ArrayCompare(pub1, t.publicKey1))
                        //{
                        //	Console.WriteLine( ByteUtil.BytesToHexString(t.privateKey1) + "|" + ByteUtil.BytesToHexString(t.publicKey1) +"|" + ByteUtil.BytesToHexString(pub1));
                        //	throw new Exception();
                        //}
                        //byte[] pub2 = new byte[32];
                        //curve.CreatePublicKeyFromPrivateKey(pub2, 0, t.privateKey2, 0);
                        //if(!ArrayCompare(pub2, t.publicKey2))
                        //{
	                       //	Console.WriteLine( ByteUtil.BytesToHexString(t.privateKey2) + "|" + ByteUtil.BytesToHexString(t.publicKey2) +"|" + ByteUtil.BytesToHexString(pub2));
                        //	throw new Exception();
                        //}

                        // hsalsa
//                        byte[] hsalsa = new byte[32];
//                        xsalsa.HSalsa20(hsalsa, 0, new byte[16], 0, t.privateKey1, 0, null, 0);
//                        ArrayCompareThr(hsalsa, t.hsalsa20PrivateKey1);

                        // shared key
                        byte[] sharedKey12 = new byte[32];
                        box.BeforeNm(sharedKey12, 0, t.publicKey1, 0,t.privateKey2,0);
                        byte[] sharedKey21 = new byte[32];
                        box.BeforeNm(sharedKey21, 0, t.publicKey2, 0, t.privateKey1, 0);
                        if(!ArrayCompare(sharedKey21, t.sharedKey))
                        {
                        	Console.WriteLine(ByteUtil.BytesToHexString(sharedKey21)+"|"+ByteUtil.BytesToHexString(t.publicKey2)+"|"+ByteUtil.BytesToHexString(t.privateKey1)+"|"+ByteUtil.BytesToHexString(t.sharedKey));
                        	throw new Exception();
                        }
                        if(!ArrayCompare(sharedKey12, t.sharedKey))
                        {
                        	Console.WriteLine(ByteUtil.BytesToHexString(sharedKey12)+"|"+ByteUtil.BytesToHexString(t.publicKey1)+"|"+ByteUtil.BytesToHexString(t.privateKey2)+"|"+ByteUtil.BytesToHexString(t.sharedKey));
                        	throw new Exception();
                        }

                        // encrypt
                        byte[] enc = new byte[t.rawData.Length + 16];
                        BoxCurve25519XSalsa20Poly1305Factory.CreateInstance().EncryptSymmetric(enc, 0, t.sharedKey, 0, t.nonce, 0, t.rawData, 0, t.rawData.Length);
                        ArrayCompareThr(enc, t.encryptedData);
                        
                        // decrypt
                        byte[] dec=new byte[t.rawData.Length];
                        BoxCurve25519XSalsa20Poly1305Factory.CreateInstance().DecryptSymmetric(dec,0,t.sharedKey,0,t.nonce,0,t.encryptedData,0,t.encryptedData.Length);
                        ArrayCompareThr(dec,t.rawData);

                        c++;
                        rateCount++;
						DateTime n=DateTime.Now;
						int elapsed=(int)TimeSpan.FromTicks(n.Ticks - dtS.Ticks).TotalSeconds;
						if( elapsed>5)
					    {
							int rate=rateCount/elapsed;
							Console.WriteLine(id + " state=" + c + " queue=" +queue.Count + " rate=" + rate + "");
							dtS=n;
							
							rateCount=0;
						}
					}
					else
					{
						if( queue.IsAddingCompleted )
							break;
						Console.Write("*");
						Thread.Sleep(10);
					}
				}
				state=1;
			} catch( Exception e)
			{
				Console.WriteLine(e);
				state=-1;
			}
			evtComplete.Set();			
		}
		public int WaitCompletion()
		{
			evtComplete.WaitOne();
			return state;
		}
		
	}
		
	
	
	
	class Program
	{
		public static void Main(string[] args)
		{
            var box = BoxCurve25519XSalsa20Poly1305Factory.CreateInstance();
			var queue=new BlockingCollection<Token>(100);
			
			int numConsumers=Environment.ProcessorCount;
			if( numConsumers==0)
				numConsumers++;
            //numConsumers = 1;
			int numProducers=numConsumers/4;
			if(numProducers==0)
				numProducers++;
			int numMsgs=50000000;

			int numMsgsPerProducer=numMsgs/numProducers;
			while( numMsgsPerProducer*numProducers<numMsgs)
				numMsgsPerProducer++;
			
			
			var producers=new Producer[numProducers];
			var consumers=new Consumer[numConsumers];
			
			
			Console.WriteLine("producers: " + numProducers);
			Console.WriteLine("consumers: " + numConsumers);
			Console.WriteLine("Tasks:     " + numMsgs );
			
			Random rnd=new Random();
			
			for(int i=0;i<numProducers;i++)
			{
				producers[i]=new Producer(i,queue,rnd.Next(),numMsgsPerProducer);
				producers[i].Start();
			}
			for(int i=0;i<numConsumers;i++)
			{
				consumers[i]=new Consumer(i,queue);
				consumers[i].Start();
			}
			for(int i=0;i<numProducers;i++)
			{
				int s=producers[i].WaitCompletion();
				if( s<=0)
					throw new Exception();
			}
			queue.CompleteAdding();
			Console.WriteLine("all producers completed");
			
			
			for(int i=0;i<numConsumers;i++)
			{
				int s=consumers[i].WaitCompletion();
                Console.WriteLine("consumer " + i +" exits with " + s);

				if( s<=0)
					throw new Exception();
			}
			Console.WriteLine("all consumers completed");
			
			
			Console.Write("Press any key to continue . . . ");
			Console.ReadKey(true);
		}
	}
}