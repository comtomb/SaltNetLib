/*
MIT License

Copyright (c) 2019 comtomb [TomB]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
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