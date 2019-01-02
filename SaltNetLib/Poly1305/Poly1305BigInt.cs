/*
 */
using System;
using System.Diagnostics;
using System.Globalization;
using System.Numerics;
using TomB.SaltNet;

namespace TomB.SaltNet.Poly1305
{
    /// <summary>
    /// BigInteger based implementation of IPoly1305
    /// very bad performance, but easy to understand
    /// </summary>
    internal class Poly1305BigInt : IPoly1305
	{
		
		private static readonly BigInteger CLAMP_MASK=BigInteger.Parse("0ffffffc0ffffffc0ffffffc0fffffff",NumberStyles.HexNumber );				
		private static readonly BigInteger TRIM_MASK=BigInteger.Parse("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",NumberStyles.HexNumber);
		private static readonly BigInteger MODULO=BigInteger.Parse("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB",NumberStyles.HexNumber);

		private static BigInteger BigIntFromLE(byte[] src,int ofs,int len)
		{
			var h= new byte[len + 1];
            Array.Copy(src, ofs, h, 0, len);
			return new BigInteger(h);
		}
		
		public Poly1305BigInt()
		{
		}
        /// <summary>
        /// <see cref="IPoly1305.Poly1305(byte[], int, byte[], int, int, byte[], int)"/>
        /// </summary>
        /// <param name="result"></param>
        /// <param name="resultOfs"></param>
        /// <param name="input"></param>
        /// <param name="inputOfs"></param>
        /// <param name="inputLen"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
		public void Poly1305(byte[] result, int resultOfs, byte[] input, int inputOfs, int inputLen, byte[] key, int keyOfs)
		{
			var r=BigIntFromLE(key,0,16) & CLAMP_MASK;
			var s=BigIntFromLE(key,16,16);
			var accu=BigInteger.Zero;
			
			int todo=inputLen;
			int pos=inputOfs;
			while(todo>0)
			{
				int blkLen=16;
				if( blkLen>todo)
					blkLen=todo;
				
				var n=BigIntFromLE(input,pos,blkLen);
				n|=BigInteger.One<<(8*blkLen);
				accu+=n;			
				accu*=r;				
				accu=BigInteger.Remainder(accu,MODULO);				
				pos+=blkLen;
				todo-=blkLen;				
			}			
			accu=accu+s;
			accu=accu & TRIM_MASK;	
            
			byte[] h=accu.ToByteArray();
			if( h.Length>16) // can be caused by h[16]==0 if h[15]>=0x80
			{
				Array.Copy(h,0,result,resultOfs,16);
			}
			else
			{
				Array.Copy(h,0,result,resultOfs,h.Length);
				for(int i=h.Length;i<16;i++)
					result[resultOfs+i]=0;				
			}
		}		
	}
}
