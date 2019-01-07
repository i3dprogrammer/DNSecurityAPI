using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI.PacketIO
{
    internal class PacketWriter : BinaryWriter
    {
        private MemoryStream m_ms;
        public PacketWriter()
        {
            m_ms = new MemoryStream();
            OutStream = m_ms;
        }

        public byte[] GetBytes()
        {
            return m_ms.ToArray();
        }
    }
}
