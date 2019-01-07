using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace DNSecurityAPI
{
    public class TCPSecurity : Interfaces.ISecurity
    {
        private object m_lock;
        private List<Packet> m_incoming;
        private List<Packet> m_outgoing;
        private TransferBuffer m_buffer;

        public TCPSecurity()
        {
            m_lock = new object();
            m_incoming = new List<Packet>();
            m_outgoing = new List<Packet>();
            m_buffer = new TransferBuffer(0x40000, 0, 0x40000);
        }


        private TransferBuffer FormatPacket(Packet packet)
        {
            var pWriter = new PacketIO.PacketWriter();
            var raw_bytes = packet.GetBytes();
            pWriter.Write((ushort)(raw_bytes.Length + 0x07));
            pWriter.Write((byte)0x00);
            pWriter.Write((ushort)(raw_bytes.Length + 0x04));
            pWriter.Write(packet.Opcode1);
            pWriter.Write(packet.Opcode2);
            pWriter.Write(raw_bytes);
            raw_bytes = Crypto.CustomXTEA.Encrypt(pWriter.GetBytes().Skip(3).ToArray());
            pWriter.Seek(0x03, System.IO.SeekOrigin.Begin);
            pWriter.Write(raw_bytes);
            return new TransferBuffer(pWriter.GetBytes(), 0, raw_bytes.Length + 0x03, false);
        }

        private bool CheckBuffer(byte[] bytes, int length)
        {
            TransferBuffer raw_buffer = new TransferBuffer(bytes, 0, length, false);
            PacketIO.PacketReader reader = new PacketIO.PacketReader(raw_buffer.Buffer);
            while (raw_buffer.Offset < raw_buffer.Size)
            {
                ushort pLength = reader.ReadUInt16();
                if (pLength + raw_buffer.Offset > raw_buffer.Size)
                    return false;

                reader.ReadByte();
                reader.ReadBytes(pLength - 3);
                raw_buffer.Offset += pLength;
            }

            return true;
        }

        public void Recv(byte[] bytes, int offset, int length)
        {
            lock(m_lock)
            {
                if (CheckBuffer(bytes, length))
                {
                    Recv(new TransferBuffer(bytes, 0, length, false));
                }
                else
                {
                    if (m_buffer.Offset + length > m_buffer.Size)
                    {
                        throw new Exception($"[SecurityAPI::Recv] Packet too large - Max size {m_buffer.Size}, Current offset {m_buffer.Offset}, Received {length}.");
                    }

                    Buffer.BlockCopy(bytes, 0, m_buffer.Buffer, m_buffer.Offset, length);
                    m_buffer.Offset += length;

                    if (CheckBuffer(m_buffer.Buffer, m_buffer.Offset))
                    {
                        Recv(new TransferBuffer(m_buffer.Buffer, 0, m_buffer.Offset, false));
                        m_buffer = new TransferBuffer(0x40000, 0, 0x40000);
                    }
                }
            }
        }

        private void Recv(TransferBuffer raw_buffer)
        {
            List<TransferBuffer> list = new List<TransferBuffer>();
            lock (m_lock)
            {
                PacketIO.PacketReader reader = new PacketIO.PacketReader(raw_buffer.Buffer);
                while (raw_buffer.Offset < raw_buffer.Size)
                {
                    ushort pLength = reader.ReadUInt16();
                    reader.ReadByte();
                    reader.ReadBytes(pLength - 3);

                    list.Add(new TransferBuffer(raw_buffer.Buffer, raw_buffer.Offset, pLength, false));
                    raw_buffer.Offset += pLength;
                }

                foreach (var item in list)
                {
                    var decryptedBytes = Crypto.CustomXTEA.Decrypt(item.Buffer.Skip(3).ToArray());
                    if (decryptedBytes.Length < 4)
                        Console.WriteLine("[SecurityAPI::Recv] Packet length cannot be lower than 4 bytes.");
                    Packet p = new Packet(decryptedBytes[0x02], decryptedBytes[0x03], decryptedBytes.Skip(0x04).ToArray());
                    p.Lock();
                    m_incoming.Add(p);
                }
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
