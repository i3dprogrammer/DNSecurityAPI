using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI.Crypto
{
    public class UDPCrypto
    {
        public static byte[] Encrypt(byte[] data)
        {
            if (data.Length < 7)
                throw new Exception("Incorrect packet length.");

            var buffer = new byte[data.Length];
            Array.Copy(data, buffer, data.Length);

            ushort buffLen = BitConverter.ToUInt16(buffer, 0);
            buffer[2] = EncryptByte(buffer[2]);
            buffer[3] = EncryptByte(buffer[3]);
            buffer[6] = EncryptByte(buffer[6]);
            buffer[2] ^= GetCryptoByte(buffLen);
            buffer[3] ^= GetCryptoByte(buffLen);

            for(int i = 0; i < buffLen; i++)
                buffer[i + 7] ^= GetCryptoByte(buffer[2] + 7 + i);

            return buffer;
        }

        public static byte[] Decrypt(byte[] data)
        {
            if (data.Length < 7)
                throw new Exception("Incorrect packet length.");

            var buffer = new byte[data.Length];
            Array.Copy(data, buffer, data.Length);

            int temp = buffer[2] + 7;

            ushort buffLen = BitConverter.ToUInt16(buffer, 0);
            buffer[2] ^= GetCryptoByte(buffLen);
            buffer[3] ^= GetCryptoByte(buffLen);
            buffer[2] = DecryptByte(buffer[2]);
            buffer[3] = DecryptByte(buffer[3]);
            buffer[6] = DecryptByte(buffer[6]);

            for (int i = 0; i < buffLen; i++)
                buffer[i + 7] ^= GetCryptoByte(temp++);

            return buffer;
        }

        private static byte DecryptByte(byte encByte)
        {
            return (byte)(Keys.UDPDecryptKey[encByte >> 5] | 8 * ((encByte & 3) | 4 * Keys.UDPDecryptKey[(encByte >> 2) & 7]));
        }


        private static byte EncryptByte(byte b)
        {
            return (byte)((b >> 3) & 3 | 4 * (Keys.UDPEncryptKey[b >> 5] | 8 * Keys.UDPEncryptKey[b & 7]));
        }

        private static byte GetCryptoByte(int length)
        {
            return Keys.UDPCryptoKey[length % 0x0D + 4];
        }
    }
}
