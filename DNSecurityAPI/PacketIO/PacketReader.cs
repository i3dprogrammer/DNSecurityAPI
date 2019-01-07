using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI.PacketIO
{
    internal class PacketReader : BinaryReader
    {
        private byte[] m_input;

        public PacketReader(byte[] input) : base(new MemoryStream(input, false))
        {
            m_input = input;
        }
    }
}
