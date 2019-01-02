namespace TomB.SaltNet
{
    /// <summary>
    /// Factory for SecureRandom
    /// </summary>
    public static class SecureRandomFactory
    {
        /// <summary>
        /// create an instance if ISecureRandom
        /// </summary>
        /// <returns></returns>
        public static ISecureRandom CreateInstance()
        {
            return new SecureRandom();
        }
    }
}
