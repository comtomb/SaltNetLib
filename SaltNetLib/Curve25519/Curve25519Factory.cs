using TomB.SaltNetLib.Curve25519;
using System;
using System.Collections.Generic;
using System.Text;

namespace TomB.SaltNet.Curve25519
{
    /// <summary>
    /// Factory for ICurve25519
    /// </summary>
    public static class Curve25519Factory
    {
        /// <summary>
        /// create an instance
        /// </summary>
        /// <returns></returns>
        public static ICurve25519 CreateInstance()
        {
            return new Curve25519Field2526();
        }
    }
}
