using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI.Crypto
{
    internal class CustomXTEA
    {
        public static byte[] Encrypt(byte[] data)
        {
            var rounds = (uint)(data.Length & 1) + 1;
            byte[] key = Utility.GetRequiredXTEAKey(data.Length);

            var keyBuffer = CreateKey(key);
            var blockBuffer = new uint[2];
            var buffer = new byte[data.Length];
            Array.Copy(data, buffer, data.Length);
            using (var stream = new MemoryStream(buffer))
            {
                using (var writer = new BinaryWriter(stream))
                {
                    for (int i = 0; i < buffer.Length; i += 8)
                    {
                        if (i + 8 > data.Length)
                            break;
                        blockBuffer[0] = BitConverter.ToUInt32(buffer, i);
                        blockBuffer[1] = BitConverter.ToUInt32(buffer, i + 4);
                        Encrypt(rounds, blockBuffer, keyBuffer);
                        writer.Write(blockBuffer[0]);
                        writer.Write(blockBuffer[1]);
                    }
                }
            }

            if (buffer.Length % 8 > 0)
            {
                int extraLength = buffer.Length % 8;
                int extraStart = buffer.Length - extraLength;
                for (int i = 0; i < extraLength; i++)
                    buffer[extraStart + i] ^= key[i];
            }

            return buffer;
        }

        public static byte[] Decrypt(byte[] data)
        {
            var rounds = (uint)(data.Length & 1) + 1;
            byte[] key = Utility.GetRequiredXTEAKey(data.Length);

            var keyBuffer = CreateKey(key);
            var blockBuffer = new uint[2];
            var buffer = new byte[data.Length];
            Array.Copy(data, buffer, data.Length);
            using (var stream = new MemoryStream(buffer))
            {
                using (var writer = new BinaryWriter(stream))
                {
                    for (int i = 0; i < buffer.Length; i += 8)
                    {
                        if (i + 8 > data.Length)
                            break;
                        blockBuffer[0] = BitConverter.ToUInt32(buffer, i);
                        blockBuffer[1] = BitConverter.ToUInt32(buffer, i + 4);
                        Decrypt(rounds, blockBuffer, keyBuffer);
                        writer.Write(blockBuffer[0]);
                        writer.Write(blockBuffer[1]);
                    }
                }
            }

            if (buffer.Length % 8 > 0)
            {
                int extraLength = buffer.Length % 8;
                int extraStart = buffer.Length - extraLength;
                for (int i = 0; i < extraLength; i++)
                    buffer[extraStart + i] ^= key[i];
            }

            return buffer;
        }

        private static uint[] CreateKey(byte[] key)
        {
            return new[] {
                BitConverter.ToUInt32(key, 0), BitConverter.ToUInt32(key, 4),
                BitConverter.ToUInt32(key, 8), BitConverter.ToUInt32(key, 12)
            };
        }

        private static void Encrypt(uint rounds, uint[] v, uint[] key)
        {
            uint v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
            for (uint i = 0; i < rounds; i++)
            {
                v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
                sum += delta;
                v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
            }
            v[0] = v0;
            v[1] = v1;
        }

        private static void Decrypt(uint rounds, uint[] v, uint[] key)
        {
            uint v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * rounds;
            for (uint i = 0; i < rounds; i++)
            {
                v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
                sum -= delta;
                v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            }
            v[0] = v0;
            v[1] = v1;
        }
    }
}
