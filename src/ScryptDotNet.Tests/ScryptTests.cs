using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ScryptDotNet.Tests;

[TestClass]
public class ScryptTests
{
    // https://www.rfc-editor.org/rfc/rfc7914#section-12
    public static IEnumerable<object[]> Rfc7914TestVectors()
    {
        yield return
        [
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            "",
            "",
            16,
            1,
            1
        ];
        yield return
        [
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            "password",
            "NaCl",
            1024,
            8,
            16
        ];
        yield return
        [
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            "pleaseletmein",
            "SodiumChloride",
            16384,
            8,
            1
        ];
        yield return
        [
            "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4",
            "pleaseletmein",
            "SodiumChloride",
            1048576,
            8,
            1
        ];
    }

    [TestMethod]
    [DynamicData(nameof(Rfc7914TestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string derivedKey, string passphrase, string salt, int N, int r, int p)
    {
        Span<byte> dk = stackalloc byte[derivedKey.Length / 2];
        Span<byte> pp = Encoding.UTF8.GetBytes(passphrase);
        Span<byte> s = Encoding.UTF8.GetBytes(salt);

        Scrypt.DeriveKey(dk, pp, s, N, r, p);

        Assert.AreEqual(derivedKey, Convert.ToHexString(dk).ToLower());
    }

    [TestMethod]
    [DataRow(0, 16, 16, 16384, 8, 1)]
    [DataRow(32, 16, 16, 0, 8, 1)]
    [DataRow(32, 16, 16, 3, 8, 1)]
    [DataRow(32, 16, 16, 2097152, 8, 1)]
    [DataRow(32, 16, 16, 16384, 0, 1)]
    [DataRow(32, 16, 16, 16384, 8, 0)]
    [DataRow(32, 16, 16, 16384, 8, 134217728)]
    public void DeriveKey_Invalid(int derivedKeySize, int passphraseSize, int saltSize, int N, int r, int p)
    {
        var dk = new byte[derivedKeySize];
        var pp = new byte[passphraseSize];
        var s = new byte[saltSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Scrypt.DeriveKey(dk, pp, s, N, r, p));
    }
}
