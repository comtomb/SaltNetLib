using TomB.SaltNet;
using System.Diagnostics;
using Xunit;

namespace SaltNetLibTest
{
    public class SecureRandomTest
    {
        [Fact]
        public void TestRandom()
        {
            var sr = new SecureRandom();
            int v0 = sr.GetInt();
            int v1 = sr.GetInt();
            Debug.WriteLine(v0 + " " + v1);
            // TODO how to test randomness... ?
        }
    }
}
