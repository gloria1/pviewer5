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
using System.Text.RegularExpressions;
using System.IO;
using Microsoft.Win32;




namespace pviewer5
{

    [Flags]
    public enum Protocols : ulong
    {
        Generic = 1,
        Ungrouped = 2,
        PcapOld = 4,
        PcapNG = 8,
        Ethernet = 0x10,
        Wifi = 0x20,
        IP4 = 0x40,
        ARP =0x80,
        IP6 = 0x100,
        TCP = 0x200,
        UDP = 0x400,
        ICMP =0x800,
        IGMP =0x1000,
        GGP =0x2000,
        DHCP4 =0x4000,
        BOOTP =0x8000,
        DNS =0x10000
    }



    public class Packet
    {
        public List<H> phlist { get; set; }

        // convenience properties to contain copies of commonly needed values,
        // so that other functions do not need to search through header list to find them
        public Protocols Prots = Protocols.Generic;     // flags for protocols present in this packet
        public ulong SrcMAC = 0;
        public ulong DestMAC = 0;
        public uint SrcIP4 { get; set; } = 0;
        public uint DestIP4 = 0;
        public uint SrcPort = 0;       // UPD or TCP port, if any
        public uint DestPort = 0;
        public UDPH udphdr = null;
        public IP4H ip4hdr = null;
        public TCPH tcphdr = null;
        public H groupprotoheader { get; set; }     // packet group logic will set this to point to the header of the protocol relevant to that group type

        public string packetdisplayinfo { get { return "Packet innermost header is: " + phlist[phlist.Count - 1].headerdisplayinfo; } }

        public byte[] PData;
        public uint Len;

        public bool qfexcluded;		// true if packet was excluded due to quickfilter - can drop once we transition to simply deleting quickfilter'ed packets

        public Packet() // empty constructor, constructs a packet with no data or headers
        {
            phlist = new List<H>();
            PData = new byte[0];
        }

        public Packet(FileStream fs, PcapFile pfh)
        {
            PcapH pch;

            phlist = new List<H>();
            Prots = 0;

            // instantiate pcap header - that constructor will start cascade of constructors for inner headers
            // PcapH constructor will also read all non-header data in
            pch = new PcapH(fs, pfh, this, 0);

            if (pfh.Type == PcapFile.PcapFileTypes.PcapNG)
                fs.Seek((long)(pch.NGBlockLen - 0x1c - pch.CapLen), SeekOrigin.Current);       // skip over any padding bytes, options and trailing block length field
        }
    }




	public partial class MainWindow : Window
	{
        public PacketViewer pview;
        public ObservableCollection<Packet> pkts { get; set; }
        // line below is deprecated
        // public ObservableCollection<Packet> exclpkts { get; set; }
        public FilterSet filters { get; set; }
        public ObservableCollection<GList> grouplistlist { get; set; }
        
    //    public static DataGrid PacketDG;    // copy of packet data grid reference, static so that other classes can refer to it
	// TEMPORARY - PROVISION FOR VIEWING QF EXLUDED PACKETS
		// WHEN NO LONGER NEEDED, ALSO DELETE
		//		CODE IN ETHER AND IP4 HEADER STATIC CONSTRUCTORS THAT CREATES THE EXTRA HF ENTRIES
		//public static DataGrid ExclDG;    // copy of packet data grid reference, static so that other classes can refer to it
		
		public MainWindow()
		{
            pkts = new ObservableCollection<Packet>();
            // line below is deprecated
            // exclpkts = new ObservableCollection<Packet>();

            filters = new FilterSet();

            grouplistlist = new ObservableCollection<GList>();
            grouplistlist.Add(new DNSGList("DNS Groups"));
            grouplistlist.Add(new DHCP4GList("DHCP4 Groups"));
            grouplistlist.Add(new TCPGList("TCP Groups"));
            grouplistlist.Add(new UDPGList("UDP Groups"));
            grouplistlist.Add(new ARPGList("ARP Groups"));
            grouplistlist.Add(new GList("Ungrouped Packets"));
            
            InitializeComponent();

			grid.DataContext = this;
			//QFExclGrid.DataContext = qfexcluded;
			//PacketDG = PacketDataGrid;
			//ExclDG = QFExclGrid;

            // try to restore window position and other settings - see "Programing WPF Second Edition" page 321
            try
            {
                Rect bounds = Properties.Settings.Default.WindowPositionMain;
                WindowState = WindowState.Normal;
                Top = bounds.Top;
                Left = bounds.Left;
                Width = bounds.Width;
                Height = bounds.Height;
                GUIUtil.Instance.Hex = Properties.Settings.Default.Hex;
                GUIUtil.Instance.UseAliases = Properties.Settings.Default.UseAliases;
            }
            catch
            { MessageBox.Show("problem retrieving stored settings"); }

            Closing += MainWindow_Closing;   // add handler for Closing event, to save window state

		}


        void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            filters.SaveToDisk(null);

            Properties.Settings.Default.WindowPositionMain = this.RestoreBounds;
            Properties.Settings.Default.Hex = GUIUtil.Instance.Hex;
            Properties.Settings.Default.UseAliases = GUIUtil.Instance.UseAliases;
            Properties.Settings.Default.Save();
            foreach (Window w in Application.Current.Windows) if (w != this) w.Close();
        }

		private void ChooseFile(object sender, RoutedEventArgs e)
		{
			PcapFile pfh;
			OpenFileDialog dlg = new OpenFileDialog();
			Nullable<bool> result;
			FileStream fs;
			Packet pkt;

            byte[] b = new byte[1000];

			dlg.Multiselect = false;
			dlg.InitialDirectory = Properties.Settings.Default.LastDirectory;
            dlg.FileName = Properties.Settings.Default.LastFile;
			result = dlg.ShowDialog();

			if (result == true)
			{
                pkts.Clear();
                // deprecated:  exclpkts.Clear();
                foreach (GList gl in grouplistlist) gl.groups.Clear();

				QuickFilterTools.QFMAC.ResetCounters();
				QuickFilterTools.QFIP4.ResetCounters();
				//foreach (PktSet set in setlist.sets) set.pkts.Clear();
				//qfexcluded.pkts.Clear();
                Properties.Settings.Default.LastDirectory = dlg.InitialDirectory;
                Properties.Settings.Default.LastFile = dlg.FileName;
				filename.Content = dlg.FileName;
				fs = new FileStream(dlg.FileName, FileMode.Open);

                pfh = new PcapFile(fs);

                while (fs.Position < fs.Length)
                {
                    pkt = new Packet(fs, pfh);
                    if (filters.Include(pkt)) pkts.Add(pkt);

                    // lines below are from older "Quickfilter" implementation - this may be permanently obsolete
                    // // NEXT LINE IS TEMPORARY - ONCE QUICKFILTER IS TRUSTED, PACKETS THAT ARE EXCLUDED SHOULD SIMPLY BE DESTROYED
                    // if (pkt.qfexcluded) exclpkts.Add(pkt);
                    // else pkts.Add(pkt);
                }

                foreach (Packet p in pkts)
                    foreach (GList gl in grouplistlist)
                        if (gl.GroupPacket(p)) break;

                foreach (TCPG tg in ((TCPGList)(grouplistlist[2])).groups)
                {
                    tg.OPL1.CopyBytes(1000, b);
                    tg.OPL2.CopyBytes(1000, b);
                }
                CollectionViewSource.GetDefaultView(grouptree.ItemsSource).Refresh();

                fs.Close();
			}
		}

		private void qfbutton(object sender, RoutedEventArgs e)
		{
			Window qfd = new QuickFilterDialog();
			qfd.ShowDialog();
		}
		private void mnmbutton(object sender, RoutedEventArgs e)
		{
			Window w1 = new MACNameMapDialog();
			w1.ShowDialog();
			CollectionViewSource.GetDefaultView(grouptree.ItemsSource).Refresh();
			// deprecated CollectionViewSource.GetDefaultView(QFExclGrid.ItemsSource).Refresh();
		}
		private void inmbutton(object sender, RoutedEventArgs e)
		{
			Window w1 = new IP4NameMapDialog();
			w1.Show();
        }

        private static void Executedtabulate(object sender, ExecutedRoutedEventArgs e)
		{
			//ulong q;

			DataGrid dg = (DataGrid)e.Source;
			DataGridTextColumn col = (DataGridTextColumn)(dg.CurrentColumn);
			if (col == null) return;
//			string path = ((Binding)(col.Binding)).Path.Path;		// col.Binding is of type BindingBase - Path property does not exist in BindingBase, so had to cast to Binding - don't know if this will cause problems.....

	//		foreach (PcapPkt p in dg.ItemsSource) q = (ulong)(col.GetCellContent(p).GetValue();
		}
		private static void CanExecutetabulate(object sender, CanExecuteRoutedEventArgs e)
		{
			e.CanExecute = true;
		}

        private void grouptree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (e.NewValue == null) return;

            if (e.NewValue.GetType() == typeof(Packet))
            {
                if (pview == null) pview = new PacketViewer();
                pview.Pkt = (Packet)(e.NewValue);

                if (!(pview.Visibility == System.Windows.Visibility.Visible)) pview.Show();
            }

            //BOOKMARK

                // IF IT IS A PACKET, OPEN PACKET VIEW WINDOW ON IT
        }

	}
}



public class ConverterHex4 : IValueConverter
{
    // converts number to display format, 4 digits fixed width if in hex, variable width if not

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return GUIUtil.Instance.UIntToString((uint)value, 4);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotSupportedException("Cannot convert back");
    }
}


