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
using System.Text.RegularExpressions;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

namespace pviewer5
{
    [Serializable]
    public class FilterSet : INotifyPropertyChanged
        // a FilterSet is a list of Filters
        // FilterSet.Include returns true if ANY Filter.Include returns true
        // FilterSet.Include also returns true if Filters is empty
    {
        public string Filename { get; set; }
        private bool _changedsincesave;
        public bool ChangedSinceSave { get { return _changedsincesave; } set { _changedsincesave = value; NotifyPropertyChanged(); } }
        private bool _changedsinceapplied;
        public bool ChangedSinceApplied { get { return _changedsinceapplied; } set { _changedsinceapplied = value; NotifyPropertyChanged(); } }
        public ObservableCollection<Filter> Filters { get; set; }

        // constructors - from a filename, and an empty constructor
        public FilterSet() : this(null) { }
        public FilterSet(string fn)
        {
            Filename = null;
            ChangedSinceApplied = false;
            ChangedSinceSave = false;
            Filters = new ObservableCollection<Filter>();
            if (fn != null)
            {
                // do stuff to load a file
            }
        }

        public bool Include(Packet pkt)  // returns true if packet should be included based on this filterset
        {
            bool include = false;   // the default result is to not include the packet, unless one of the filters says to include it

            if (Filters.Count() == 0) return true;
            foreach (Filter f in Filters)
                if (f.Active)
                    if (f.Match(pkt))
                    {
                        include = f.InclusionFilter;
                        break;
                    }

            return include;
        }

        public void SaveToDisk(string fn)
        // if filename argument is null, open a save as dialog
        {
            SaveFileDialog dlg;
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            if (fn == null)
            {
                dlg = new SaveFileDialog();
                dlg.InitialDirectory = "c:\\pviewer\\";
                dlg.DefaultExt = ".filterset";
                dlg.OverwritePrompt = true;
                if (dlg.ShowDialog() == false) return;
                else Filename = dlg.FileName;
            }
            else Filename = fn;
            fs = new FileStream(Filename, FileMode.OpenOrCreate);
            formatter.Serialize(fs, Filters);
            fs.Close();
            ChangedSinceSave = false;
        }

        public void LoadFromDisk(string fn)
        // if filename is null, open an openfiledialog
        {
            OpenFileDialog dlg;
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            if (fn == null)
            {
                dlg = new OpenFileDialog();
                dlg.InitialDirectory = "c:\\pviewer\\";
                dlg.DefaultExt = ".filterset";
                dlg.Multiselect = false;

                if (dlg.ShowDialog() == true) Filename = dlg.FileName;
                else return;
            }

            fs = new FileStream(Filename, FileMode.Open);

            try
            {
                Filters = ((ObservableCollection<Filter>)(formatter.Deserialize(fs)));
                ChangedSinceSave = false;
            }
            catch
            {
                MessageBox.Show("File not read");
            }
            finally
            {
                fs.Close();
            }

        }

        // implement INotifyPropertyChanged interface
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

    }


    [Serializable]
    public class Filter : INotifyPropertyChanged
    // list of FilterItems
    // Filter.Include returns true only if ALL FilterItem.Match calls return true
    {
        private bool _active;
        public bool Active
        {
            get { return _active; }
            set
            {
                _active = value;
                NotifyPropertyChanged();
                if (Parent != null) Parent.ChangedSinceApplied = true;
                if (Parent != null) Parent.ChangedSinceSave = true;
            }
        }
        public bool InclusionFilter { get; set; }
        public ObservableCollection<FilterItem> filterlist { get; set; }
        public FilterSet Parent = null;
        public string DisplayInfo
        {
            get
            {
                return String.Format("Filter with {0} items", filterlist.Count());
            }
        }

        // constructors
        public Filter() : this(null) { }
        public Filter(FilterSet parent)  // this is the master, general constructor
        {
            Active = true;
            InclusionFilter = true;
            filterlist = new ObservableCollection<FilterItem>();
            Parent = parent;
        }

        public bool Match(Packet pkt)
        // must match on ALL filter items to return true
        {
            if (filterlist.Count() == 0) return false;
            foreach (FilterItem fi in filterlist) if (fi.Match(pkt) == false) return false;
            return true;
        }

        // implement INotifyPropertyChanged interface
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

    }

    [Serializable]
    public class FilterItem
    {
        public uint Value {get; set;}
        public uint Mask { get; set; }     // bit mask applied to Value and to the packet being tested
        public Relations Relation { get; set; }
        public string DisplayInfo
        {
            get
            {
                string r;
                switch(Relation)
                {
                    case Relations.Equal: r = "="; break;
                    case Relations.NotEqual: r = "!="; break;
                    case Relations.LessThan: r = "<"; break;
                    case Relations.LessThanOrEqual: r = "<="; break;
                    case Relations.GreaterThan: r = ">"; break;
                    case Relations.GreaterThanOrEqual: r = ">="; break;
                    default: r = "invalid relation"; break;
                }

                return "IPv4 Source " + r + IP4Util.Instance.IP4ToString(Value) + ", Mask=" + IP4Util.Instance.IP4ToString(Mask);
            }
        }

        public bool Match(Packet pkt)
        {
            uint mval;

            mval = (pkt.SrcIP4 & Mask);
            switch (Relation)
            {
                case Relations.Equal: return (mval == Value);
                case Relations.NotEqual: return (mval != Value);
                case Relations.LessThan: return (mval < Value);
                case Relations.LessThanOrEqual: return (mval <= Value);
                case Relations.GreaterThan: return (mval > Value);
                case Relations.GreaterThanOrEqual: return (mval >= Value);
                case Relations.Undefined:
                default:
                    return false;
            }


        }

        public FilterItem() : this(0, 0, Relations.Undefined) { }
        public FilterItem(uint value, uint mask, Relations rel)
        {
            Value = value;
            Mask = mask;
            Relation = rel;
        }


    }

    public enum Relations : int
    {
        Equal = 1,
        NotEqual = 2,
        LessThan = 3,
        LessThanOrEqual = 4,
        GreaterThan = 5,
        GreaterThanOrEqual = 6,
        Undefined = 99999    
    }


}