using TomB.SaltNet.Salsa20;
using System;
using System.Collections.Generic;
using System.Text;

namespace TomB.SaltNet.Salsa20
{
    /// <summary>
    /// Factory to create a IXSalsa20 implementation
    /// </summary>
    public static class XSalsa20Factory
    {
        /// <summary>
        /// create a new instance of a IXSalsa20
        /// </summary>
        /// <returns>new IXSalsa20</returns>
        public static IXSalsa20 CreateInstance()
        {
            return new XSalsa20Impl();
        }
    }
}
