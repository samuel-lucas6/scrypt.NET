using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ScryptDotNet;

public static class Scrypt
{
    private static int _blockSize;

    public static void DeriveKey(Span<byte> derivedKey, ReadOnlySpan<byte> passphrase, ReadOnlySpan<byte> salt, int N, int r, int p)
    {
        if (derivedKey.Length == 0) { throw new ArgumentOutOfRangeException(nameof(derivedKey), derivedKey.Length, $"{nameof(derivedKey)} must be greater than 0 bytes long."); }
        if (r < 1) { throw new ArgumentOutOfRangeException(nameof(r), r, $"{nameof(r)} must be greater than 0."); }
        if (N < 1 || N > int.MaxValue / (128 * r) || (N & (N - 1)) != 0) { throw new ArgumentOutOfRangeException(nameof(N), N, $"{nameof(N)} must be between 1 and 2^(128 * r / 8) as well as a power of 2."); }
        if (p < 1 || p > 137438953440 / (128 * r)) { throw new ArgumentOutOfRangeException(nameof(r), r, $"{nameof(r)} must be between 1 and ((2^32-1) * 32) / (128 * r)."); }

        _blockSize = 128 * r;
        Span<byte> b = new byte[_blockSize * p];
        Span<byte> v = new byte[_blockSize * N];
        Span<byte> xy = new byte[_blockSize * 2];
        Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, destination: b, iterations: 1, HashAlgorithmName.SHA256);

        for (int i = 0; i < p; i++) {
            sROMix(b.Slice(i * _blockSize, _blockSize), r, N, v, xy);
        }

        Rfc2898DeriveBytes.Pbkdf2(passphrase, salt: b, derivedKey, iterations: 1, HashAlgorithmName.SHA256);
    }

    private static void sROMix(Span<byte> b, int r, int N, Span<byte> v, Span<byte> xy)
    {
        Span<byte> x = xy[.._blockSize];
        Span<byte> y = xy[_blockSize..];

        b.CopyTo(x);

        for (int i = 0; i < N; i++) {
            x.CopyTo(v.Slice(i * _blockSize, _blockSize));
            BlockMix(x, y, r);
        }

        for (int i = 0; i < N; i++) {
            int j = (int)BinaryPrimitives.ReadUInt64LittleEndian(x.Slice((2 * r - 1) * 64, sizeof(ulong))) & (N - 1);
            Span<byte> vj = v.Slice(j * _blockSize, _blockSize);
            for (int z = 0; z < x.Length; z++) {
                x[z] ^= vj[z];
            }
            BlockMix(x, y, r);
        }

        x.CopyTo(b);
    }

    private static void BlockMix(Span<byte> b, Span<byte> y, int r)
    {
        Span<byte> x = stackalloc byte[64];
        b.Slice((2 * r - 1) * 64, x.Length).CopyTo(x);

        for (int i = 0; i < 2 * r; i++) {
            Span<byte> bi = b.Slice(i * 64, x.Length);
            for (int j = 0; j < x.Length; j++) {
                x[j] ^= bi[j];
            }
            Salsa8Core(x, x);

            x.CopyTo(y.Slice(i * 64, x.Length));
        }

        for (int i = 0; i < r; i++) {
            y.Slice(i * 2 * 64, 64).CopyTo(b.Slice(i * 64, 64));
        }
        for (int i = 0; i < r; i++) {
            y.Slice((i * 2 + 1) * 64, 64).CopyTo(b.Slice((i + r) * 64, 64));
        }
    }

    private static void Salsa8Core(Span<byte> output, ReadOnlySpan<byte> input)
    {
        uint j0 = BinaryPrimitives.ReadUInt32LittleEndian(input[..4]);
        uint j1 = BinaryPrimitives.ReadUInt32LittleEndian(input[4..8]);
        uint j2 = BinaryPrimitives.ReadUInt32LittleEndian(input[8..12]);
        uint j3 = BinaryPrimitives.ReadUInt32LittleEndian(input[12..16]);
        uint j4 = BinaryPrimitives.ReadUInt32LittleEndian(input[16..20]);
        uint j5 = BinaryPrimitives.ReadUInt32LittleEndian(input[20..24]);
        uint j6 = BinaryPrimitives.ReadUInt32LittleEndian(input[24..28]);
        uint j7 = BinaryPrimitives.ReadUInt32LittleEndian(input[28..32]);
        uint j8 = BinaryPrimitives.ReadUInt32LittleEndian(input[32..36]);
        uint j9 = BinaryPrimitives.ReadUInt32LittleEndian(input[36..40]);
        uint j10 = BinaryPrimitives.ReadUInt32LittleEndian(input[40..44]);
        uint j11 = BinaryPrimitives.ReadUInt32LittleEndian(input[44..48]);
        uint j12 = BinaryPrimitives.ReadUInt32LittleEndian(input[48..52]);
        uint j13 = BinaryPrimitives.ReadUInt32LittleEndian(input[52..56]);
        uint j14 = BinaryPrimitives.ReadUInt32LittleEndian(input[56..60]);
        uint j15 = BinaryPrimitives.ReadUInt32LittleEndian(input[60..]);

        uint x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15;

        for (int i = 0; i < 8; i += 2) {
            x4 ^= uint.RotateLeft(x0 + x12, 7);  x8 ^= uint.RotateLeft(x4 + x0, 9);
            x12 ^= uint.RotateLeft(x8 + x4,13);  x0 ^= uint.RotateLeft(x12 + x8,18);
            x9 ^= uint.RotateLeft(x5 + x1, 7);  x13 ^= uint.RotateLeft(x9 + x5, 9);
            x1 ^= uint.RotateLeft(x13 + x9,13);  x5 ^= uint.RotateLeft(x1 + x13,18);
            x14 ^= uint.RotateLeft(x10 + x6, 7);  x2 ^= uint.RotateLeft(x14 + x10, 9);
            x6 ^= uint.RotateLeft(x2 + x14,13);  x10 ^= uint.RotateLeft(x6 + x2,18);
            x3 ^= uint.RotateLeft(x15 + x11, 7);  x7 ^= uint.RotateLeft(x3 + x15, 9);
            x11 ^= uint.RotateLeft(x7 + x3,13);  x15 ^= uint.RotateLeft(x11 + x7,18);

            x1 ^= uint.RotateLeft(x0 + x3, 7);  x2 ^= uint.RotateLeft(x1 + x0, 9);
            x3 ^= uint.RotateLeft(x2 + x1,13);  x0 ^= uint.RotateLeft(x3 + x2,18);
            x6 ^= uint.RotateLeft(x5 + x4, 7);  x7 ^= uint.RotateLeft(x6 + x5, 9);
            x4 ^= uint.RotateLeft(x7 + x6,13);  x5 ^= uint.RotateLeft(x4 + x7,18);
            x11 ^= uint.RotateLeft(x10 + x9, 7);  x8 ^= uint.RotateLeft(x11 + x10, 9);
            x9 ^= uint.RotateLeft(x8 + x11,13);  x10 ^= uint.RotateLeft(x9 + x8,18);
            x12 ^= uint.RotateLeft(x15 + x14, 7);  x13 ^= uint.RotateLeft(x12 + x15, 9);
            x14 ^= uint.RotateLeft(x13 + x12,13);  x15 ^= uint.RotateLeft(x14 + x13,18);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(output[..4], x0 + j0);
        BinaryPrimitives.WriteUInt32LittleEndian(output[4..8], x1 + j1);
        BinaryPrimitives.WriteUInt32LittleEndian(output[8..12], x2 + j2);
        BinaryPrimitives.WriteUInt32LittleEndian(output[12..16], x3 + j3);
        BinaryPrimitives.WriteUInt32LittleEndian(output[16..20], x4 + j4);
        BinaryPrimitives.WriteUInt32LittleEndian(output[20..24], x5 + j5);
        BinaryPrimitives.WriteUInt32LittleEndian(output[24..28], x6 + j6);
        BinaryPrimitives.WriteUInt32LittleEndian(output[28..32], x7 + j7);
        BinaryPrimitives.WriteUInt32LittleEndian(output[32..36], x8 + j8);
        BinaryPrimitives.WriteUInt32LittleEndian(output[36..40], x9 + j9);
        BinaryPrimitives.WriteUInt32LittleEndian(output[40..44], x10 + j10);
        BinaryPrimitives.WriteUInt32LittleEndian(output[44..48], x11 + j11);
        BinaryPrimitives.WriteUInt32LittleEndian(output[48..52], x12 + j12);
        BinaryPrimitives.WriteUInt32LittleEndian(output[52..56], x13 + j13);
        BinaryPrimitives.WriteUInt32LittleEndian(output[56..60], x14 + j14);
        BinaryPrimitives.WriteUInt32LittleEndian(output[60..], x15 + j15);
    }
}
