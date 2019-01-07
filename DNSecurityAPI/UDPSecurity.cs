using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI
{
    public class UDPSecurity : Interfaces.ISecurity
    {
        private object m_lock;
        private List<Packet> m_incoming;
        private List<Packet> m_outgoing;
        private TransferBuffer m_buffer;
        public uint count = 0x00;

        public UDPSecurity()
        {
            m_lock = new object();
            m_incoming = new List<Packet>();
            m_outgoing = new List<Packet>();
            m_buffer = new TransferBuffer(0x1000, 0, 0x1000);
        }

        private TransferBuffer FormatPacket(Packet packet)
        {
            var bytes = packet.GetBytes();
            if (packet.Opcode == 0x00)
                return new TransferBuffer(bytes, 0, bytes.Length, false);

            using (var pWriter = new PacketIO.PacketWriter())
            {
                pWriter.Write((ushort)(count | 2));
                pWriter.Write((byte)0x00);
                pWriter.Write((ushort)(bytes.Length));
                pWriter.Write(packet.Opcode1);
                pWriter.Write(packet.Opcode2);
                pWriter.Write((ushort)(bytes.Length + 7));
                pWriter.Write((byte)0x00); //USUALLY 0, UNKNOWN CURRENTLY
                pWriter.Write(bytes);

                var pbytes = pWriter.GetBytes().Skip(3).ToArray();

                var data = Crypto.UDPCrypto.Encrypt(pbytes);
                pWriter.Seek(0x03, System.IO.SeekOrigin.Begin);
                pWriter.Write(data);

                data = pWriter.GetBytes();
                data[2] = (byte)((data.Length + 0x78) - (data.Sum(x => x) & 0xFF));

                count += 8;
                return new TransferBuffer(data, 0, data.Length, false);
            }
        }

        public void Recv(byte[] bytes, int offset, int length)
        {
            lock (m_lock)
            {
                Recv(new TransferBuffer(bytes, 0, length, false));
            }
        }

        private void Recv(TransferBuffer raw_buffer)
        {
            try
            {
                Packet p = null;
                if (raw_buffer.Size >= 10)
                {
                    var d_bytes = Crypto.UDPCrypto.Decrypt(raw_buffer.Buffer.Skip(3).ToArray());
                    p = new Packet(d_bytes[0x02], d_bytes[0x03], d_bytes.Skip(0x07).ToArray());
                }
                else
                    p = new Packet(0x00, 0x00, raw_buffer.Buffer);

                p.Lock();
                m_incoming.Add(p);
            } catch (Exception ex)
            {
                Console.WriteLine("@@@@@@@@@@@@@@@@@@@@@@@@@@");
                Utility.Hexdump(raw_buffer.Buffer);
                Console.WriteLine(ex.Message + "\n" + ex.StackTrace);
                Console.WriteLine("@@@@@@@@@@@@@@@@@@@@@@@@@@");
            }
        }

        public void Send(Packet packet)
        {
            lock (m_lock)
            {
                m_outgoing.Add(packet);
            }
        }

        public List<KeyValuePair<TransferBuffer, Packet>> TransferOutgoing()
        {
            lock (m_lock)
            {
                var list = new List<KeyValuePair<TransferBuffer, Packet>>(m_outgoing.Count);
                foreach (var p in m_outgoing)
                    list.Add(new KeyValuePair<TransferBuffer, Packet>(FormatPacket(p), p));
                m_outgoing = new List<Packet>();
                return list;
            }
        }

        public List<Packet> TransferIncoming()
        {
            lock (m_lock)
            {
                var result = new List<Packet>(m_incoming);
                m_incoming = new List<Packet>();
                return result;
            }
        }
    }
}
