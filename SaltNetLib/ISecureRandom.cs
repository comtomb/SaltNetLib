namespace TomB.SaltNet
{
    /// <summary>
    /// Secure Random
    /// </summary>
    public interface ISecureRandom
    {
        /// <summary>
        /// get a randomized byte array of length len
        /// </summary>
        /// <param name="len"></param>
        /// <returns></returns>
        byte[] GetBytes(int len);
        /// <summary>
        /// get a random int 0 to Int32.MaxValue
        /// </summary>
        /// <returns></returns>
        int GetInt();
        /// <summary>
        /// get a random long 0 to Int64.MaxValue
        /// </summary>
        /// <returns></returns>
        long GetLong();
        /// <summary>
        /// randomize a byte array
        /// </summary>
        /// <param name="bytes"></param>
        void Randomize(byte[] bytes);
        /// <summary>
        /// randomize a part of a byte array
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="ofs"></param>
        /// <param name="len"></param>
        void Randomize(byte[] bytes, int ofs, int len);
    }
}