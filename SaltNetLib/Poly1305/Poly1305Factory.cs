using System;
using System.Collections.Generic;
using System.Text;
using TomB.SaltNet.Poly1305;

namespace TomB.SaltNet.Poly1305
{
    /// <summary>
    /// Factory for IPoly1305
    /// </summary>
    public static class Poly1305Factory
    {
        /// <summary>
        /// create a new instance
        /// </summary>
        /// <returns></returns>
        public static IPoly1305 CreateInstance()
        {
        	return new Poly1305Field();
        }
    }
}
