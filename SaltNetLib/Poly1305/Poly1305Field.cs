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
    /// Helper class for int[] Field based modular arithmetic
    /// </summary>
    internal class Field26
    {
        /// <summary>
        /// all Fields have 26 bit
        /// </summary>
        private const int FIELD_LEN=26;
        /// <summary>
        /// mask
        /// </summary>
        private const int FIELD_MASK=(1<<FIELD_LEN)-1;
                
        private const int FIELDS=5;
        
        public static readonly Field26 Zero = new Field26();


        private int[] field=new int[FIELDS];

        
        public Field26()
        {
        	
        }
        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="src"></param>
        /// <param name="srcOfs"></param>
        /// <param name="srcLen"></param>
        public Field26(byte[] src,int srcOfs,int srcLen)
        {
        	var h=new int[FIELDS];
        	for(int i=0;i<srcLen;i++)
        	{
        		int bitPos=i*8;
        		int f=bitPos/FIELD_LEN;
        		int b=bitPos%FIELD_LEN;
        		if(b+8<FIELD_LEN)
        			field[f]|=((int)src[srcOfs+i])<<b;
        		else
        		{
        			int r=FIELD_LEN-b;
        			field[f]|=(((int)src[srcOfs+i])&((1<<r)-1))<<b;
        			field[f+1]=((int)src[srcOfs+i])>>r;
        		}
        		
        	}
        	
        }
        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="other"></param>
        public Field26(Field26 other)
        {
        	for(int i=0;i<FIELDS;i++)
        		field[i]=other.field[i];
        }
        /// <summary>
        /// Add
        /// </summary>
        /// <param name="b"></param>
        public void AddReduceNoCarrySelf( Field26 b )
        {
        	field[0]+=b.field[0];
        	field[1]+=b.field[1];
        	field[2]+=b.field[2];
        	field[3]+=b.field[3];
        	field[4]+=b.field[4];
        }
        /// <summary>
        /// Add and reduce
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static Field26 AddReduce( Field26 a,Field26 b )
        {
            int carry=0;
            var res=new Field26();
            for(int i=0;i<FIELDS;i++)
            {
            	int s=a.field[i]+b.field[i]+carry;
            	res.field[i]=s&FIELD_MASK;
            	carry=s>>FIELD_LEN;
            }
            res.field[0]+=5*carry;
            return res;
        }
        /// <summary>
        /// add and and reduce
        /// </summary>
        /// <param name="b"></param>
        public void AddReduceSelf( Field26 b )
        {
            int carry=0;
            for(int i=0;i<FIELDS;i++)
            {
            	int s=field[i]+b.field[i]+carry;
            	field[i]=s&FIELD_MASK;
            	carry=s>>FIELD_LEN;
            }
            field[0]+=5*carry;
        }
        /// <summary>
        /// output
        /// </summary>
        /// <returns></returns>
        public String Dump()
        {
        	String s="";
        	for(int i=0;i<FIELDS;i++)
        		s=s+field[i].ToString("X8") + " ";
        	return s;
        }
        /// <summary>
        /// Add
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static Field26 Add( Field26 a,Field26 b )
        {
            var res=new Field26();
            for(int i=0;i<FIELDS;i++)
            	res.field[i]=a.field[i]+b.field[i];
            
            return res;
        }
        /// <summary>
        /// binary AND
        /// 
        /// </summary>
        /// <param name="a">first operand.</param>
        /// <param name="b">second operand. Must be (coefficient) reduced </param>
        /// <returns></returns>
        public static Field26 And(Field26 a, Field26 b)
        {
            var res=new Field26();
            int ca=0;
            for(int i=0;i<FIELDS;i++)
            {
            	int s=a.field[i]+ca;
            	ca=s>>FIELD_LEN;
            	res.field[i]=s & FIELD_MASK  & b.field[i];
            }
            return res;
        }
        
        /// <summary>
        /// schoolbook multiplication
        /// </summary>
        /// <param name="b"></param>
        public void MultiplyReduceSelf(Field26 b)
        {
            long a0b0=(long)field[0] * (long)b.field[0];
            long a0b1=(long)field[0] * (long)b.field[1];
            long a0b2=(long)field[0] * (long)b.field[2];
            long a0b3=(long)field[0] * (long)b.field[3];
            long a0b4=(long)field[0] * (long)b.field[4];

            long a1b0=(long)field[1] * (long)b.field[0];
            long a1b1=(long)field[1] * (long)b.field[1];
            long a1b2=(long)field[1] * (long)b.field[2];
            long a1b3=(long)field[1] * (long)b.field[3];
            long a1b4=(long)field[1] * (long)b.field[4];

            long a2b0=(long)field[2] * (long)b.field[0];
            long a2b1=(long)field[2] * (long)b.field[1];
            long a2b2=(long)field[2] * (long)b.field[2];
            long a2b3=(long)field[2] * (long)b.field[3];
            long a2b4=(long)field[2] * (long)b.field[4];

            long a3b0=(long)field[3] * (long)b.field[0];
            long a3b1=(long)field[3] * (long)b.field[1];
            long a3b2=(long)field[3] * (long)b.field[2];
            long a3b3=(long)field[3] * (long)b.field[3];
            long a3b4=(long)field[3] * (long)b.field[4];

            long a4b0=(long)field[4] * (long)b.field[0];
            long a4b1=(long)field[4] * (long)b.field[1];
            long a4b2=(long)field[4] * (long)b.field[2];
            long a4b3=(long)field[4] * (long)b.field[3];
            long a4b4=(long)field[4] * (long)b.field[4];
            

            long r0=a0b0  	+ 5 * (a4b1+a1b4 + a3b2+a2b3);
            long r1=a0b1+a1b0  	+ 5 * (a4b2+a2b4+a3b3);        	
            long r2=a0b2+a2b0+a1b1 	+ 5 * (a4b3+a3b4);            	
            long r3=a0b3+a1b2+a2b1+a3b0	+ 5 * (a4b4);            	
            long r4=a0b4+a1b3+a2b2+a3b1+a4b0;
            	            
            
           	long carry=5*(r4>>FIELD_LEN);
            r4&=FIELD_MASK;

            long s0=r0+carry;
            field[0]=(int)(s0&FIELD_MASK);
            carry=s0>>FIELD_LEN;

            long s1=r1+carry;
            field[1]=(int)(s1&FIELD_MASK);
            carry=s1>>FIELD_LEN;
            
            long s2=r2+carry;
            field[2]=(int)(s2&FIELD_MASK);
            carry=s2>>FIELD_LEN;

            long s3=r3+carry;
            field[3]=(int)(s3&FIELD_MASK);
            carry=s3>>FIELD_LEN;
                        
            long s4=r4+carry;
            field[4]=(int)(s4&FIELD_MASK);
            carry=s4>>FIELD_LEN;
            
            field[0]+=5*(int)carry;
            
            

        }
        /// <summary>
        /// set a bit
        /// </summary>
        /// <param name="bit"></param>
        public void SetBitSelf(int bit)
        {
            int f=bit/FIELD_LEN;
            int b=bit%FIELD_LEN;
            field[f]|=1<<b;
        }
        public void ToBytesLE(byte[] result,int resultOfs)
        {
        	// normalize first! take care of 2^130-4, 2^130-3, 2^130-2, 2^130-1, 2^130-4 
			// same approach as in Curve25519
			int q = (5*field[4]  + (1<<(FIELD_LEN-1)))>>FIELD_LEN;
			q = (field[0] + q) >> FIELD_LEN;
			q = (field[1] + q) >> FIELD_LEN;
			q = (field[2] + q) >> FIELD_LEN;
			q = (field[3] + q) >> FIELD_LEN;
			q = (field[4] + q) >> FIELD_LEN;        	

        	int carry=5*q;
        	
        	for(int i=0;i<FIELDS;i++)
        	{
        		int s=field[i]+carry;
        		field[i]=s&FIELD_MASK;
        		carry=s>>FIELD_LEN;
        	}
        	
        	
            result[resultOfs+0]=(byte) ((field[0]>>0)&0xff);
            result[resultOfs+1]=(byte) ((field[0]>>8)&0xff);
            result[resultOfs+2]=(byte) ((field[0]>>16)&0xff);
            result[resultOfs+3]=(byte) (((field[0]>>24)&0x03) | ((field[1])&0x3f)<<2);
            result[resultOfs+4]=(byte) ((field[1]>>6)&0xff);
            result[resultOfs+5]=(byte) ((field[1]>>14)&0xff);
            result[resultOfs+6]=(byte) (((field[1]>>22)&0x0f) | ((field[2])&0xf)<<4);
            result[resultOfs+7]=(byte) ((field[2]>>4)&0xff);
            result[resultOfs+8]=(byte) ((field[2]>>12)&0xff);
            result[resultOfs+9]=(byte) (((field[2]>>20)&0x3f) | ((field[3])&0x03)<<6);
            result[resultOfs+10]=(byte) ((field[3]>>2)&0xff);
            result[resultOfs+11]=(byte) ((field[3]>>10)&0xff);
            result[resultOfs+12]=(byte) ((field[3]>>18)&0xff);
            result[resultOfs+13]=(byte) ((field[4]>>0)&0xff);
            result[resultOfs+14]=(byte) ((field[4]>>8)&0xff);
            result[resultOfs+15]=(byte) ((field[4]>>16)&0xff);
        }

    }

    /// <summary>
    /// Field based implementation of IPoly1305
    /// </summary>
    internal class Poly1305Field : IPoly1305
	{
		
		private static readonly Field26 TRIM_MASK=new Field26(new byte[] {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},0,16 );
		private static readonly Field26 CLAMP_MASK=new Field26(new byte[] {0xFF,0xFF,0xFF,0x0F,0xFC,0xFF,0xFF,0x0F,0xFC,0xFF,0xFF,0x0F,0xFC,0xFF,0xFF,0x0F},0,16  );
		
		public Poly1305Field()
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
			var rField=new Field26(key,0,16) ;
			rField=Field26.And(rField, CLAMP_MASK );
			var sField=new Field26(key,16,16);
			var accuField=new Field26();

            int todo =inputLen;
			int pos=inputOfs;
			while(todo>0)
			{
                int blkLen =16;
				if( blkLen>todo)
					blkLen=todo;
				
				var nField=new Field26(input,pos,blkLen);
                nField.SetBitSelf(8 * blkLen);

                accuField.AddReduceNoCarrySelf(nField);
                accuField.MultiplyReduceSelf( rField);                
               
                pos += blkLen;
				todo-=blkLen;
                

			}
			
            accuField = Field26.Add(accuField, sField);		// add module 2^130
            accuField = Field26.And(accuField, TRIM_MASK );

            accuField.ToBytesLE(result, resultOfs);
		}		
	}
}
