using System;

namespace TomB.SaltNet
{
    /// <summary>
    /// Exception for Decryption
    /// </summary>
    public class DecryptionException : Exception
    {
        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="msg"></param>
        public DecryptionException(String msg)
            : base(msg)
        {

        }
    }
}
