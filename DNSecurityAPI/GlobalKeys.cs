using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI
{
    public class Keys
    {
        public static byte[] XTEAKey;
        public static byte[] UDPCryptoKey;
        public static byte[] UDPDecryptKey;
        public static byte[] UDPEncryptKey;
        public static List<byte[]> Base64Keys;

        public static void Initialize(byte[] xteaKey, byte[] udpCryptoKey, byte[] udpDecryptKey, byte[] udpEncryptKey, List<byte[]> base64Keys)
        {
            XTEAKey = xteaKey;
            UDPCryptoKey = udpCryptoKey;
            UDPDecryptKey = udpDecryptKey;
            UDPEncryptKey = udpEncryptKey;
            Base64Keys = base64Keys;
        }
    }
}
