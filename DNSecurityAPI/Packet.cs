using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DNSecurityAPI.PacketIO;

namespace DNSecurityAPI
{
    public class Packet
    {
        private object m_lock;
        private bool m_locked;
        private byte m_opcode1;
        private byte m_opcode2;
        private PacketWriter m_writer;
        private PacketReader m_reader;
        private byte[] m_reader_bytes;
        public byte Opcode1 => m_opcode1;
        public byte Opcode2 => m_opcode2;
        public ushort Opcode
        {
            get
            {
                return (ushort)((m_opcode1 * 0x100) | m_opcode2);
            }
        }

        public Packet(byte opcode1, byte opcode2)
        {
            m_lock = new object();
            m_opcode1 = opcode1;
            m_opcode2 = opcode2;

            m_writer = new PacketWriter();
        }

        public Packet(byte opcode1, byte opcode2, byte[] bytes)
        {
            m_lock = new object();
            m_opcode1 = opcode1;
            m_opcode2 = opcode2;
            m_writer = new PacketWriter();
            WriteUInt8Array(bytes);
        }

        public byte[] GetBytes()
        {
            lock (m_lock)
            {
                if (!m_locked)
                    return m_writer.GetBytes();
                return m_reader_bytes;
            }
        }

        public void Lock()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    m_reader_bytes = m_writer.GetBytes();
                    m_reader = new PacketReader(m_reader_bytes);
                    m_writer.Close();
                    m_writer = null;
                    m_locked = true;
                }
            }
        }

        public long SeekRead(long offset, SeekOrigin orgin)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot SeekRead on an unlocked packet.");
                }
                return m_reader.BaseStream.Seek(offset, orgin);
            }
        }

        public int RemainingRead()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot SeekRead on an unlocked packet.");
                }
                return (int)(m_reader.BaseStream.Length - m_reader.BaseStream.Position);
            }
        }

        public byte ReadUInt8()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadByte();
            }
        }

        public sbyte ReadInt8()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadSByte();
            }
        }

        public ushort ReadUInt16()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadUInt16();
            }
        }

        public short ReadInt16()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadInt16();
            }
        }

        public uint ReadUInt32()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadUInt32();
            }
        }

        public int ReadInt32()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadInt32();
            }
        }

        public ulong ReadUInt64()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadUInt64();
            }
        }

        public long ReadInt64()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadInt64();
            }
        }

        public float ReadSingle()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadSingle();
            }
        }

        public double ReadDouble()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                return m_reader.ReadDouble();
            }
        }

        public string ReadAscii()
        {
            return ReadAscii(1252);
        }

        public string ReadAscii(int codepage)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                ushort count = m_reader.ReadUInt16();
                byte[] bytes = m_reader.ReadBytes(count);
                return Encoding.GetEncoding(codepage).GetString(bytes);
            }
        }

        public string ReadUnicode()
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                ushort num = m_reader.ReadUInt16();
                byte[] bytes = m_reader.ReadBytes(num * 2);
                return Encoding.Unicode.GetString(bytes);
            }
        }

        public string ReadFixedAscii(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                    throw new Exception("Cannot read from an unlocked packet.");
                List<byte> buff = new List<byte>();
                for (int i = 0; i < count; i++)
                {
                    var b = m_reader.ReadByte();
                    if (b != 0x00)
                        buff.Add(b);
                }
                return Encoding.ASCII.GetString(buff.ToArray());
            }
        }

        public byte[] ReadUInt8Array(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                byte[] array = new byte[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadByte();
                }
                return array;
            }
        }

        public sbyte[] ReadInt8Array(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                sbyte[] array = new sbyte[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadSByte();
                }
                return array;
            }
        }

        public ushort[] ReadUInt16Array(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                ushort[] array = new ushort[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadUInt16();
                }
                return array;
            }
        }

        public short[] ReadInt16Array(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                short[] array = new short[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadInt16();
                }
                return array;
            }
        }

        public uint[] ReadUInt32Array(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                uint[] array = new uint[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadUInt32();
                }
                return array;
            }
        }

        public int[] ReadInt32Array(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                int[] array = new int[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadInt32();
                }
                return array;
            }
        }

        public ulong[] ReadUInt64Array(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                ulong[] array = new ulong[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadUInt64();
                }
                return array;
            }
        }

        public long[] ReadInt64Array(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                long[] array = new long[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadInt64();
                }
                return array;
            }
        }

        public float[] ReadSingleArray(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                float[] array = new float[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadSingle();
                }
                return array;
            }
        }

        public double[] ReadDoubleArray(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                double[] array = new double[count];
                for (int i = 0; i < count; i++)
                {
                    array[i] = m_reader.ReadDouble();
                }
                return array;
            }
        }

        public string[] ReadAsciiArray(int count)
        {
            return ReadAsciiArray(1252, count);
        }

        public string[] ReadAsciiArray(int codepage, int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                string[] array = new string[count];
                for (int i = 0; i < count; i++)
                {
                    ushort count2 = m_reader.ReadUInt16();
                    byte[] bytes = m_reader.ReadBytes(count2);
                    array[i] = Encoding.UTF7.GetString(bytes);
                }
                return array;
            }
        }

        public string[] ReadUnicodeArray(int count)
        {
            lock (m_lock)
            {
                if (!m_locked)
                {
                    throw new Exception("Cannot Read from an unlocked Packet.");
                }
                string[] array = new string[count];
                for (int i = 0; i < count; i++)
                {
                    ushort num = m_reader.ReadUInt16();
                    byte[] bytes = m_reader.ReadBytes(num * 2);
                    array[i] = Encoding.Unicode.GetString(bytes);
                }
                return array;
            }
        }

        public long SeekWrite(long offset, SeekOrigin orgin)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot SeekWrite on a locked Packet.");
                }
                return m_writer.BaseStream.Seek(offset, orgin);
            }
        }

        public void WriteUInt8(byte value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteInt8(sbyte value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteUInt16(ushort value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteInt16(short value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteUInt32(uint value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteInt32(int value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteUInt64(ulong value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteInt64(long value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteSingle(float value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteDouble(double value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(value);
            }
        }

        public void WriteAscii(string value)
        {
            WriteAscii(value, 1252);
        }

        public void WriteAscii(string value, int code_page)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                byte[] bytes = Encoding.GetEncoding(code_page).GetBytes(value);
                string @string = Encoding.UTF7.GetString(bytes);
                byte[] bytes2 = Encoding.Default.GetBytes(@string);
                m_writer.Write((ushort)bytes2.Length);
                m_writer.Write(bytes2);
            }
        }

        public void WriteFixedAscii(string value, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                    throw new Exception("Cannot write to a locked packet.");

                byte[] bytes = Encoding.ASCII.GetBytes(value);
                for (int i = 0; i < count; i++)
                {
                    if (i < value.Length)
                        m_writer.Write((byte)value[i]);
                    else
                        m_writer.Write((byte)0x00);
                }
            }
        }

        public void WriteUnicode(string value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                byte[] bytes = Encoding.Unicode.GetBytes(value);
                m_writer.Write((ushort)value.ToString().Length);
                m_writer.Write(bytes);
            }
        }

        public void WriteUInt8(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write((byte)(Convert.ToUInt64(value) & 0xFF));
            }
        }

        public void WriteInt8(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write((sbyte)(Convert.ToInt64(value) & 0xFF));
            }
        }

        public void WriteUInt16(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write((ushort)(Convert.ToUInt64(value) & 0xFFFF));
            }
        }

        public void WriteInt16(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write((ushort)(Convert.ToInt64(value) & 0xFFFF));
            }
        }

        public void WriteUInt32(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write((uint)(Convert.ToUInt64(value) & uint.MaxValue));
            }
        }

        public void WriteInt32(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write((int)(Convert.ToInt64(value) & uint.MaxValue));
            }
        }

        public void WriteUInt64(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(Convert.ToUInt64(value));
            }
        }

        public void WriteInt64(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(Convert.ToInt64(value));
            }
        }

        public void WriteSingle(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(Convert.ToSingle(value));
            }
        }

        public void WriteDouble(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                m_writer.Write(Convert.ToDouble(value));
            }
        }

        public void WriteAscii(object value)
        {
            WriteAscii(value, 1252);
        }

        public void WriteAscii(object value, int code_page)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                byte[] bytes = Encoding.GetEncoding(code_page).GetBytes(value.ToString());
                string @string = Encoding.UTF7.GetString(bytes);
                byte[] bytes2 = Encoding.Default.GetBytes(@string);
                m_writer.Write((ushort)bytes2.Length);
                m_writer.Write(bytes2);
            }
        }

        public void WriteUnicode(object value)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                byte[] bytes = Encoding.Unicode.GetBytes(value.ToString());
                m_writer.Write((ushort)value.ToString().Length);
                m_writer.Write(bytes);
            }
        }

        public void WriteUInt8Array(byte[] values)
        {
            if (m_locked)
            {
                throw new Exception("Cannot Write to a locked Packet.");
            }
            m_writer.Write(values);
        }

        public void WriteUInt8Array(byte[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteUInt16Array(ushort[] values)
        {
            WriteUInt16Array(values, 0, values.Length);
        }

        public void WriteUInt16Array(ushort[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteInt16Array(short[] values)
        {
            WriteInt16Array(values, 0, values.Length);
        }

        public void WriteInt16Array(short[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteUInt32Array(uint[] values)
        {
            WriteUInt32Array(values, 0, values.Length);
        }

        public void WriteUInt32Array(uint[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteInt32Array(int[] values)
        {
            WriteInt32Array(values, 0, values.Length);
        }

        public void WriteInt32Array(int[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteUInt64Array(ulong[] values)
        {
            WriteUInt64Array(values, 0, values.Length);
        }

        public void WriteUInt64Array(ulong[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteInt64Array(long[] values)
        {
            WriteInt64Array(values, 0, values.Length);
        }

        public void WriteInt64Array(long[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteSingleArray(float[] values)
        {
            WriteSingleArray(values, 0, values.Length);
        }

        public void WriteSingleArray(float[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteDoubleArray(double[] values)
        {
            WriteDoubleArray(values, 0, values.Length);
        }

        public void WriteDoubleArray(double[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    m_writer.Write(values[i]);
                }
            }
        }

        public void WriteAsciiArray(string[] values, int codepage)
        {
            WriteAsciiArray(values, 0, values.Length, codepage);
        }

        public void WriteAsciiArray(string[] values, int index, int count, int codepage)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteAscii(values[i], codepage);
                }
            }
        }

        public void WriteAsciiArray(string[] values)
        {
            WriteAsciiArray(values, 0, values.Length, 1252);
        }

        public void WriteAsciiArray(string[] values, int index, int count)
        {
            WriteAsciiArray(values, index, count, 1252);
        }

        public void WriteUnicodeArray(string[] values)
        {
            WriteUnicodeArray(values, 0, values.Length);
        }

        public void WriteUnicodeArray(string[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteUnicode(values[i]);
                }
            }
        }

        public void WriteUInt8Array(object[] values)
        {
            WriteUInt8Array(values, 0, values.Length);
        }

        public void WriteUInt8Array(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteUInt8(values[i]);
                }
            }
        }

        public void WriteInt8Array(object[] values)
        {
            WriteInt8Array(values, 0, values.Length);
        }

        public void WriteInt8Array(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteInt8(values[i]);
                }
            }
        }

        public void WriteUInt16Array(object[] values)
        {
            WriteUInt16Array(values, 0, values.Length);
        }

        public void WriteUInt16Array(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteUInt16(values[i]);
                }
            }
        }

        public void WriteInt16Array(object[] values)
        {
            WriteInt16Array(values, 0, values.Length);
        }

        public void WriteInt16Array(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteInt16(values[i]);
                }
            }
        }

        public void WriteUInt32Array(object[] values)
        {
            WriteUInt32Array(values, 0, values.Length);
        }

        public void WriteUInt32Array(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteUInt32(values[i]);
                }
            }
        }

        public void WriteInt32Array(object[] values)
        {
            WriteInt32Array(values, 0, values.Length);
        }

        public void WriteInt32Array(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteInt32(values[i]);
                }
            }
        }

        public void WriteUInt64Array(object[] values)
        {
            WriteUInt64Array(values, 0, values.Length);
        }

        public void WriteUInt64Array(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteUInt64(values[i]);
                }
            }
        }

        public void WriteInt64Array(object[] values)
        {
            WriteInt64Array(values, 0, values.Length);
        }

        public void WriteInt64Array(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteInt64(values[i]);
                }
            }
        }

        public void WriteSingleArray(object[] values)
        {
            WriteSingleArray(values, 0, values.Length);
        }

        public void WriteSingleArray(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteSingle(values[i]);
                }
            }
        }

        public void WriteDoubleArray(object[] values)
        {
            WriteDoubleArray(values, 0, values.Length);
        }

        public void WriteDoubleArray(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteDouble(values[i]);
                }
            }
        }

        public void WriteAsciiArray(object[] values, int codepage)
        {
            WriteAsciiArray(values, 0, values.Length, codepage);
        }

        public void WriteAsciiArray(object[] values, int index, int count, int codepage)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteAscii(values[i].ToString(), codepage);
                }
            }
        }

        public void WriteAsciiArray(object[] values)
        {
            WriteAsciiArray(values, 0, values.Length, 1252);
        }

        public void WriteAsciiArray(object[] values, int index, int count)
        {
            WriteAsciiArray(values, index, count, 1252);
        }

        public void WriteUnicodeArray(object[] values)
        {
            WriteUnicodeArray(values, 0, values.Length);
        }

        public void WriteUnicodeArray(object[] values, int index, int count)
        {
            lock (m_lock)
            {
                if (m_locked)
                {
                    throw new Exception("Cannot Write to a locked Packet.");
                }
                for (int i = index; i < index + count; i++)
                {
                    WriteUnicode(values[i].ToString());
                }
            }
        }
    }
}
