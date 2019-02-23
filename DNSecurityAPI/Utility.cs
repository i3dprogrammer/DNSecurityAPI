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

        public static void Hexdump(Packet packet, bool S_C, bool udp = false)
        {
            var bytes = packet.GetBytes();
            Console.WriteLine("[{0}] [{1:X2}-{2:X2}] [{3} bytes] [{4}]", S_C ? "S -> C" : "C -> S", packet.Opcode1, packet.Opcode2, bytes.Length, udp ? "UDP" : "TCP");

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

        public static byte[] HexdumpBytes(Packet packet)
        {
            return HexdumpBytes(packet.GetBytes());
        }

        public static byte[] HexdumpBytes(byte[] bytes)
        {
            using (var memStream = new System.IO.MemoryStream())
            {
                using (var bwriter = new System.IO.BinaryWriter(memStream))
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
                        bwriter.Write($"{i.ToString("x6")}: {hexBytes}    {strdump}" + Environment.NewLine);
                    }
                    bwriter.Write(Encoding.ASCII.GetBytes("\n"), 0, 1);
                    return memStream.ToArray();
                }
            }
        }
    }
}
