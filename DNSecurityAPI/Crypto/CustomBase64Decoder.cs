using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI.Crypto
{
    public class CustomBase64Decoder
    {
        public static byte[] Decode(byte[] encoded_data, byte tIndex)
        {
            var b64_table = Keys.Base64Keys[tIndex];
            var len = encoded_data.Length;
            int i = 0;
            int j = 0;
            byte l = 0;
            int size = 0;
            byte[] tmp = new byte[4];
            byte[] buf = new byte[3];

            while (len-- > 0)
            {
                tmp[i++] = encoded_data[j++];

                if (i == 4)
                {
                    for (i = 0; i < 4; ++i)
                    {
                        for (l = 0; l < 64; ++l)
                        {
                            if (tmp[i] == b64_table[l])
                            {
                                tmp[i] = l;
                                break;
                            }
                        }
                    }

                    buf[0] = (byte)((tmp[0] << 2) + ((tmp[1] & 0x30) >> 4));
                    buf[1] = (byte)(((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2));
                    buf[2] = (byte)(((tmp[2] & 0x3) << 6) + tmp[3]);

                    for (i = 0; i < 3; ++i)
                    {
                        encoded_data[size++] = buf[i];
                    }

                    i = 0;
                }
            }

            return encoded_data.Take(size).ToArray();
        }
    }
}
