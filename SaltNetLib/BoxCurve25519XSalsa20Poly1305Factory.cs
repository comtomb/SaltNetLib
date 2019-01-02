using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SaltNetTest")]

namespace TomB.SaltNet
{
    /// <summary>
    /// Factory for IBoxCurve25519XSalsa20Poly1305
    /// </summary>
    public static class BoxCurve25519XSalsa20Poly1305Factory
    {
        /// <summary>
        /// Create new instance of IBoxCurve25519XSalsa20Poly1305
        /// </summary>
        /// <returns></returns>
        public static IBoxCurve25519XSalsa20Poly1305 CreateInstance()
        {
            return new BoxCurve25519XSalsa20Poly1305();
        }
    }
}
