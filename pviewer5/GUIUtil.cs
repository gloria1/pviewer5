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
    public class GUIUtil : INotifyPropertyChanged
    // class containing:
    //      utility functions related to displaying hex and decimal numbers (value converters, etc.)
    //      global state variables for whether to show them in hex and whether to show aliases
    // this is implemented as a dynamic class as a Singleton, i.e., there can only ever be one instance
    // this is because static classes cannot implement interfaces (or at least INotifyPropertyChanged)
    {
        private static readonly GUIUtil instance = new GUIUtil();
        public static GUIUtil Instance { get { return instance; } }

        private bool _hex;
        public bool Hex { get { return _hex; } set { _hex = value; NotifyPropertyChanged("Hex"); } }
        private bool _usealiases;
        public bool UseAliases { get { return _usealiases; } set { _usealiases = value; NotifyPropertyChanged("UseAliases"); } }

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public uint? StringToUInt(string s)
        // converts string to numerical uint value, parsing as hex or decimal depending on global flag
        // returns null if string cannot be parsed
        {
            string regIP4 = (Hex ? "^([a-fA-F0-9]{0,2}.){0,3}[a-fA-F0-9]{0,2}$" : "^([0-9]{0,3}.){0,3}[0-9]{0,3}$");
            NumberStyles style = (Hex ? NumberStyles.HexNumber : NumberStyles.Integer);
            string[] IP4bits = new string[4];

            try
            {
                return uint.Parse(s, style);
            }
            catch (FormatException ex)
            {
                if (Regex.IsMatch(s, regIP4))
                {
                    IP4bits = Regex.Split(s, "\\.");
                    // resize array to 4 - we want to tolerate missing dots, i.e., user entering less than 4 segments,
                    // split will produce array with number of elements equal to nmber of dots + 1
                    Array.Resize<string>(ref IP4bits, 4);

                    for (int i = 0; i < 4; i++) { IP4bits[i] = "0" + IP4bits[i]; }
                    return uint.Parse(IP4bits[0], style) * 0x0000000001000000 +
                            uint.Parse(IP4bits[1], style) * 0x0000000000010000 +
                            uint.Parse(IP4bits[2], style) * 0x0000000000000100 +
                            uint.Parse(IP4bits[3], style) * 0x0000000000000001;
                }
            }

            return null;
        }

        public string UIntToString(uint value, int width)
        // fixed width iff width>0 and Hex==true
        {
            string s;

            if (Hex) s = String.Format("{0:x8}", value);
            else s = String.Format("{0}", value);

            if (Hex && (width > 0))
            {
                if (width <= s.Length) s = s.Substring(s.Length - width);
                else s = s.PadLeft(width - s.Length, '0');
            }

            return s;
        }

    }

}
