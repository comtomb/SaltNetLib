using System;
using System.Security.Cryptography;

namespace TomB.SaltNet
{
    /// <summary>
    /// Secure Random Number generation
    /// </summary>
    internal class SecureRandom : ISecureRandom
    {
        /// <summary>
        /// let the framework do the job...
        /// </summary>
        private RNGCryptoServiceProvider crypto;
        /// <summary>
        /// constructor
        /// </summary>
        public SecureRandom()
        {
            crypto = new RNGCryptoServiceProvider();
        }
        /// <summary>
        /// (positive) single random from 0 to Int32.MaxValue
        /// </summary>
        /// <returns></returns>
        public int GetInt()
        {
            var b = GetBytes(4);
            b[0] &= 0x7f;
            return ByteUtilNetLib.ByteUtil.GetI32BE(b, 0);
        }
        /// <summary>
        /// positive single random from 0 to Int64.MaxValue
        /// </summary>
        /// <returns></returns>
        public long GetLong()
        {
            var b = GetBytes(0);
            b[0] &= 0x7f;
            return ByteUtilNetLib.ByteUtil.GetI64BE(b, 0);
        }
        /// <summary>
        /// randomized array
        /// </summary>
        /// <param name="len"></param>
        /// <returns></returns>
        public byte[] GetBytes(int len)
        {
            if (len < 0)
                throw new ArgumentException();
            var arr = new byte[len];
            Randomize(arr);
            return arr;
        }
        /// <summary>
        /// randomize an array
        /// </summary>
        /// <param name="bytes"></param>
        public void Randomize(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException();
            crypto.GetBytes(bytes);
        }
        /// <summary>
        /// randomize part of an array
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="ofs"></param>
        /// <param name="len"></param>
        public void Randomize(byte[] bytes, int ofs, int len)
        {
            if (bytes == null)
                throw new ArgumentNullException();
            if (len < 0 || ofs < 0 || bytes.Length - ofs < len)
                throw new ArgumentException();
            // TODO use crypto.GetBytes(bytes,ofs,len) as soon as .NET451 is eliminated
            if(ofs==0 && len==bytes.Length)
            {
                crypto.GetBytes(bytes);
            }
            else
            {               
                var hlp = new byte[len];
                crypto.GetBytes(hlp);
                hlp.CopyTo(bytes, ofs);
            }
        }
    }
}
