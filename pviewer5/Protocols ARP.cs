using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using Microsoft.Win32;



namespace pviewer5
{
    public class ARPH : H
    {
        public uint HWType { get; set; }
        public uint Prot { get; set; }
        public uint HWAddrLen { get; set; }
        public uint ProtAddrLen { get; set; }
        public uint Opn { get; set; }
        public ulong SenderHW { get; set; }
        public uint SenderProt { get; set; }
        public ulong TargetHW { get; set; }
        public uint TargetProt { get; set; }
        public override string headerdisplayinfo
        {
            get
            {
                MACConverterNumberOrAlias mc = new MACConverterNumberOrAlias();
                IP4ConverterNumberOrAlias ic = new IP4ConverterNumberOrAlias();
                if (Prot == 0x0800)     // IPv4
                    return String.Format("ARP OpCode: {0:X4}, HWType: {1:X4}, Prot {2:X4}", Opn, HWType, Prot);
                else
                    return String.Format("ARP OpCode: {0:X4}, HWType: {1:X4}, Prot {2:X4}", Opn, HWType, Prot)
                            + ", SenderHW " + mc.Convert(SenderHW, null, null, null)
                            + String.Format(", SenderProto {0:X8}", SenderProt)
                            + ", TargetHW " + mc.Convert(TargetHW, null, null, null)
                            + String.Format(", TargetProto {0:X8}", TargetProt);
            }
        }


        public ARPH(FileStream fs, PcapFile pfh, Packet pkt, uint i)
        {

            if ((pkt.Len - i) < 0x8) return;
            HWType = (uint)pkt.PData[i++]  * 0x100 + (uint)pkt.PData[i++] ;
            Prot = (uint)pkt.PData[i++]  * 0x100 + (uint)pkt.PData[i++] ;
            HWAddrLen = (uint)pkt.PData[i++] ;
            ProtAddrLen = (uint)pkt.PData[i++] ;
            Opn = (uint)pkt.PData[i++]  * 0x100 + (uint)pkt.PData[i++] ;

            if ((pkt.Len - i) < (2 * HWAddrLen + 2 * ProtAddrLen)) return;

            // HANDLE OTHER ADDR LEN VARIATIONS
            if ((HWAddrLen != 6) || (ProtAddrLen != 4)) return;

            SenderHW = (ulong)pkt.PData[i++]  * 0x0010000000000 + (ulong)pkt.PData[i++]  * 0x000100000000 + (ulong)pkt.PData[i++]  * 0x000001000000 + (ulong)pkt.PData[i++]  * 0x000000010000 + (ulong)pkt.PData[i++]  * 0x000000000100 + (ulong)pkt.PData[i++] ;
            SenderProt = (uint)pkt.PData[i++]  * 0x000001000000 + (uint)pkt.PData[i++]  * 0x000000010000 + (uint)pkt.PData[i++]  * 0x000000000100 + (uint)pkt.PData[i++] ;
            TargetHW = (ulong)pkt.PData[i++]  * 0x0010000000000 + (ulong)pkt.PData[i++]  * 0x000100000000 + (ulong)pkt.PData[i++]  * 0x000001000000 + (ulong)pkt.PData[i++]  * 0x000000010000 + (ulong)pkt.PData[i++]  * 0x000000000100 + (ulong)pkt.PData[i++] ;
            TargetProt = (uint)pkt.PData[i++]  * 0x000001000000 + (uint)pkt.PData[i++]  * 0x000000010000 + (uint)pkt.PData[i++]  * 0x000000000100 + (uint)pkt.PData[i++] ;

            // set generic header properties
            headerprot = Protocols.ARP;
            payloadindex = i;
            payloadlen = (int)(pkt.Len - i);

            // set packet-level convenience properties
            pkt.Prots |= Protocols.ARP;

            // add to packet header list
            pkt.phlist.Add(this);
        }
    }

    public class ARPG : G
    {
        // define properties of a specific group here
        public uint HWType;      // these are the header fields that define an ARP group
        public uint Prot;
        public ulong SenderHW;
        public uint SenderProt;
        public uint TargetProt;
        public override string groupdisplayinfo
        {
            get
            {
                MACConverterNumberOrAlias mc = new MACConverterNumberOrAlias();
                IP4ConverterNumberOrAlias ic = new IP4ConverterNumberOrAlias();
                if (Prot == 0x0800)     // IPv4
                    return String.Format("ARP Group, HWType: {0:X4}, Prot {1:X4}", HWType, Prot)
                            + ", SenderHW " + mc.Convert(SenderHW, null, null, null)
                            + ", SenderIP4 " + ic.Convert(SenderProt, null, null, null)
                            + ", TargetIP4 " + ic.Convert(TargetProt, null, null, null)
                            + String.Format(", Packets in Group = {0:X2}", L.Count());

                else
                    return String.Format("ARP Group, HWType: {0:X4}, Prot {1:X4}", HWType, Prot)
                            + ", SenderHW " + mc.Convert(SenderHW, null, null, null)
                            + String.Format(", SenderProto {0:X8}", SenderProt)
                            + String.Format(", TargetProto {0:X8}", TargetProt)
                            + String.Format(", Packets in Group = {0:X2}", L.Count());
            }
        }

        public ARPG(Packet pkt) : base(pkt)
        {
            // note: base class constructor is called first (due to : base(pkt) above)

            // set group properties here
            ARPH arph = null;
            foreach (H ph in pkt.phlist) if (ph.headerprot == Protocols.ARP) { arph = (ARPH)ph; break; }
            HWType = arph.HWType;
            Prot = arph.Prot;
            SenderHW = arph.SenderHW;
            SenderProt = arph.SenderProt;
            TargetProt = arph.TargetProt;

            if (SenderProt == TargetProt) Complete = true;   // if this is a gratuitous ARP, mark the group complete immediately

        }

        public override bool Belongs(Packet pkt, H h)        // returns true if pkt belongs to group
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this save this function from having to search for the protocol header in pkt.phlist each time it is called

            // rules for membership in an ARP packet group:
            //      the first packet found is included (it may be a reply, if the request occurred before the capture file)
            //      if the packet is a gratuitous ARP, group is immediately marked complete
            //      further packets will be included if they are a valid response to the first packet (i.e., sender == original target, and opcode == 2)
            // ARP group header specification members:
            //      HWType
            //      Prot
            //      SenderHW address
            //      SenderProt address
            //      TargetProt address

            // can assume GList.CanBelong has returned true

            if (h == null) return false;     // if no ARP header, return false now
            ARPH arph = (ARPH)h;

            if ((arph.TargetHW == SenderHW) && (arph.TargetProt == SenderProt) && (arph.SenderProt == TargetProt))   // if this packet is a proper response to the original request....
                if ((arph.HWType == HWType) && (arph.Prot == Prot) && (arph.Opn == 2))       //  ... and if the hardware type and protocol fields match, and opcode == 2 
                {
                    Complete = true;                                            // then this packet completes the group
                    return true;                                                // return true
                }
            return false;
        }

    }
    public class ARPGList : GList       // generic ARP of a packet group class
    {
        // declare and initialize headerselector for this class of GList
        public override Protocols headerselector { get; set; }



        public ARPGList(string n) : base(n)
        {
            // set headerselector to protocol header that G.GroupPacket should extract
            headerselector = Protocols.ARP;
        }



        public override bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
        {
            // h argument: the GList.GroupPacket function can pass in a reference to a relevant protocol header, so CanBelong does not have to search the header list every time it is called
            return (h != null);     // packet can belong to an ARP group if it has an ARP header
        }
        public override G StartNewGroup(Packet pkt, H h)      // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this saves this function from having to search for the protocol header in pkt.phlist each time it is called

            if (h != null) return new ARPG(pkt);     // replace "true" with test for other qualifications for this packet to start a new group
            else return null;       // return null if cannot start a group with this packet
        }
    }


}
