using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI
{
    public class Utility
    {
        internal static byte[] GetRequiredXTEAKey(int length)
        {
            var key = Keys.XTEAKey.Skip(((length & 0xFF) << 4) + 4).Take(16).ToArray();
            return key;
        }

        public static void Hexdump(Packet packet, bool S_C)
        {
            var bytes = packet.GetBytes();
            if (S_C)
                Console.WriteLine($"[S -> C] [{packet.Opcode1.ToString("X2")}-{packet.Opcode2.ToString("X2")}] [{bytes.Length} bytes]");
            else
                Console.WriteLine($"[C -> S] [{packet.Opcode1.ToString("X2")}-{packet.Opcode2.ToString("X2")}] [{bytes.Length} bytes]");

            for (int i = 0; i < bytes.Length; i += 16)
            {
                string strdump = "";
                string hexBytes = "";
                for (int j = 0; j < 16; j++)
                {
                    if (i + j >= bytes.Length)
                    {
                        strdump += " ";
                        hexBytes += "   ";
                    }
                    else
                    {
                        if (!char.IsControl((char)bytes[i + j]))
                            strdump += (char)bytes[i + j];
                        else
                            strdump += ".";

                        hexBytes += bytes[i + j].ToString("X2") + " ";
                    }

                }
                Console.WriteLine($"{i.ToString("x6")}: {hexBytes}    {strdump}");
            }
            Console.WriteLine();
        }

        public static void Hexdump(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i += 16)
            {
                string strdump = "";
                string hexBytes = "";
                for (int j = 0; j < 16; j++)
                {
                    if (i + j >= bytes.Length)
                    {
                        strdump += " ";
                        hexBytes += "   ";
                    }
                    else
                    {
                        if (!char.IsControl((char)bytes[i + j]))
                            strdump += (char)bytes[i + j];
                        else
                            strdump += ".";

                        hexBytes += bytes[i + j].ToString("X2") + " ";
                    }

                }
                Console.WriteLine($"{i.ToString("x6")}: {hexBytes}    {strdump}");
            }
            Console.WriteLine();
        }
    }
}
