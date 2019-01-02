using System;
using System.Collections.Generic;
using System.Text;

namespace TomB.SaltNet
{
    /// <summary>
    /// Poly1305: see RFC 7539 
    /// https://tools.ietf.org/html/rfc7539
    /// </summary>
    public interface IPoly1305
    {
        /// <summary>
        /// Poly1305 MAC
        /// </summary>
        /// <param name="result"></param>
        /// <param name="resultOfs"></param>
        /// <param name="input"></param>
        /// <param name="inputOfs"></param>
        /// <param name="inputLen"></param>
        /// <param name="key"></param>
        /// <param name="keyOfs"></param>
        void Poly1305(byte[] result, int resultOfs, byte[] input, int inputOfs, int inputLen, byte[] key, int keyOfs);
    }
}
