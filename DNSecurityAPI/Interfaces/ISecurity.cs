using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSecurityAPI.Interfaces
{
    public interface ISecurity
    {
        void Recv(byte[] bytes, int offset, int length);
        void Send(Packet packet);
        List<KeyValuePair<TransferBuffer, Packet>> TransferOutgoing();
        List<Packet> TransferIncoming();
    }
}
