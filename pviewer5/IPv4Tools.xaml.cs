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
    
    public class IP4Util : INotifyPropertyChanged
    // class containing:
    //      utility functions related to IP4 addresses (value converters, etc.)
    // this is implemented as a dynamic class as a Singleton, i.e., there can only ever be one instance
    // this is because static classes cannot implement interfaces (or at least INotifyPropertyChanged)
    {
        private static readonly IP4Util instance = new IP4Util();
        public static IP4Util Instance { get { return instance; } }

         public IP4namemapclass map = new IP4namemapclass()
        {
                {0x00000000, "ALL ZEROES"},
        };

        // private constructor below was set up per the "singleton" pattern, so that no further instances of this class could be created
        // however, for some reason this caused the data binding to IP4Hex to stop working, so i have commented this out
        /* private IP4Util()
        // constructor is private, so no one else can call it - the singleton instance was created in the initialization of Instance above
        {
            return;
        }*/

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public uint? StringToIP4(string s)
        // converts string to numerical IP4 value
        // returns null if string cannot be parsed
        {
            string regIP4 = (GUIUtil.Instance.Hex ? "^([a-fA-F0-9]{0,2}.){0,3}[a-fA-F0-9]{0,2}$" : "^([0-9]{0,3}.){0,3}[0-9]{0,3}$");
            NumberStyles style = (GUIUtil.Instance.Hex ? NumberStyles.HexNumber : NumberStyles.Integer);
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

        public string IP4ToString(uint value)
        {
            uint[] b = new uint[4];
            string s;

            b[0] = ((value & 0xff000000) / 0x1000000);
            b[1] = ((value & 0xff0000) / 0x10000);
            b[2] = ((value & 0xff00) / 0x100);
            b[3] = ((value & 0xff) / 0x1);

            if (GUIUtil.Instance.Hex) s = String.Format("{0:x2}.{1:x2}.{2:x2}.{3:x2}", b[0], b[1], b[2], b[3]);
            else s = String.Format("{0}.{1}.{2}.{3}", b[0], b[1], b[2], b[3]);

            return s;
        }


        [Serializable]
        public class IP4namemapclass : Dictionary<uint, string>
        // data model for a mapping of IP4 addresses to aliases
        {
            // need the following constructor (from ISerializable, which is inherited by Dictionary)
            protected IP4namemapclass(SerializationInfo info, StreamingContext ctx) : base(info, ctx) { }
            // need to explicitly declare an empty constructor, because without this, new tries to use the above constructor
            public IP4namemapclass() { }

            public IP4nametableclass maptotable()	// transfers IP4namemap dictionary to a table to support a datagrid
            {
                IP4nametableclass table = new IP4nametableclass();

                foreach (uint k in this.Keys) table.Add(new inmtableitem(k, this[k]));
                return table;
            }
        }

        [Serializable]
        public class IP4nametableclass : ObservableCollection<inmtableitem>, INotifyPropertyChanged
        // view model for mapping of IP4 values to aliases
        {
            public IP4namemapclass tabletomap()	// transfers IP4name table from a datagrid to a IP4namemap dictionary
            {
                IP4namemapclass map = new IP4namemapclass();

                // need to catch exceptions in case table has duplicate IP4 entries - if this is the case, just return null
                try
                {
                    foreach (inmtableitem i in this) map.Add(i.IP4, i.alias);
                }
                catch
                {
                    return null;
                }
                return map;
            }
        }

        public class inmtableitem
        {
            public uint IP4 { get; set; }
            public string alias { get; set; }

            public inmtableitem(uint u, string s)
            {
                this.IP4 = u;
                this.alias = s;
            }
        }

    }



    public class ValidateIP4Number : ValidationRule
    {
        // validates that string is valid as either raw hex number or IP4-formatted hex number (using StringToIP4 function)
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            uint? v = 0;

            // try to parse as a raw IP4 address
            v = IP4Util.Instance.StringToIP4((string)value);
            if (v != null) return new ValidationResult(true, "Valid IP4 Address");
            else return new ValidationResult(false, "Not a valid IP4 address");
        }
    }

    public class ValidateIP4NumberOrAlias : ValidationRule
    {
        // validates that string is valid as either raw hex number or IP4-formatted hex number (using StringToIP4 function)
        //      or that string is a valid entry in alias registry

        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            uint? v = 0;

            // first try to parse as a raw IP4 address
            v = IP4Util.Instance.StringToIP4((string)value);
            if (v != null) return new ValidationResult(true, "Valid IP4 Address");
            // if that failed, see if string exists in IP4namemap
            foreach (uint u in IP4Util.Instance.map.Keys)
                if ((string)value == IP4Util.Instance.map[u])
                    return new ValidationResult(true, "Valid IP4 Address");
            return new ValidationResult(false, "Not a valid IP4 address");
        }
    }

    public class IP4ConverterNumberOnly : IValueConverter
    {
        // converts number to/from display format IP4 address, without checking the IP4 alias dictionary

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return IP4Util.Instance.IP4ToString((uint)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            ulong? v = 0;

            // first try to parse as a raw IP4 address
            v = IP4Util.Instance.StringToIP4((string)value);
            if (v != null) return v;

            // we should never get to this point, since validation step will not pass unless value is either valid raw IP4 
            // however, just in case put up a messagebox and return 0
            MessageBox.Show("ConvertBack could not process a raw IP4 address.  Why did this pass validation????");
            return 0;
        }
    }




    public class IP4ConverterNumberOrAlias : IValueConverter
    {
        // converts number to/from display format IP4 address, including translating aliases

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (GUIUtil.Instance.UseAliases && IP4Util.Instance.map.ContainsKey((uint)value))
                return IP4Util.Instance.map[(uint)value];
            else return IP4Util.Instance.IP4ToString((uint)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            uint? v = 0;

            // first try to parse as a raw IP4 address
            v = IP4Util.Instance.StringToIP4((string)value);
            if (v != null) return v;

            // if that failed, see if string exists in IP4namemap
            foreach (uint u in IP4Util.Instance.map.Keys)
                if ((string)value == IP4Util.Instance.map[u])
                    return u;

            // we should never get to this point, since validation step will not pass unless value is either valid raw IP4 or existing entry in IP4namemap
            // however, just in case put up a messagebox and return 0
            MessageBox.Show("ConvertBack could not process as either raw IP4 address or entry in IP4namemap.  Why did this pass validation????");
            return 0;
        }
    }

    public class IP4MultiConverterNumberOrAlias : IMultiValueConverter
    {
        // converts number to/from display format IP4 address, including translating aliases
        // also takes value of IP4Hex as an argument

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            if (GUIUtil.Instance.UseAliases && IP4Util.Instance.map.ContainsKey((uint)values[0]))
                return IP4Util.Instance.map[(uint)values[0]];
            else return IP4Util.Instance.IP4ToString((uint)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }



    public partial class IP4NameMapDialog : Window, INotifyPropertyChanged
	{
		public static RoutedCommand inmaddrow = new RoutedCommand();

		public IP4Util.IP4nametableclass dgtable { get; set; }

        private bool _chgsincesave = false;
        public bool changedsincesavedtodisk { get { return _chgsincesave; } set { _chgsincesave = value; NotifyPropertyChanged(); } }
        private bool _chgsinceapplied = false;
        public bool changedsinceapplied { get { return _chgsinceapplied; } set { _chgsinceapplied = value; NotifyPropertyChanged(); } }

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }


        public IP4NameMapDialog()
		{
			CommandBinding inmaddrowbinding;
            
			dgtable = IP4Util.Instance.map.maptotable();

            InitializeComponent();
            buttonbar.DataContext = this;
			INMDG.DataContext = this;
			inmaddrowbinding = new CommandBinding(inmaddrow, Executedaddrow, CanExecuteaddrow);
			INMDG.CommandBindings.Add(inmaddrowbinding);
			inmaddrowmenuitem.CommandTarget = INMDG;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model (logical focus? keyboard focus?), so you have to set the command target explicitly
            
		}

		public bool IsValid(DependencyObject parent)
		{
			// this is from http://stackoverflow.com/questions/17951045/wpf-datagrid-validation-haserror-is-always-false-mvvm

			if (Validation.GetHasError(parent))
				return false;

			// Validate all the bindings on the children
			for (int i = 0; i != VisualTreeHelper.GetChildrenCount(parent); ++i)
			{
				DependencyObject child = VisualTreeHelper.GetChild(parent, i);
				if (!IsValid(child)) { return false; }
			}

			return true;
		}

		private void inmApply(object sender, RoutedEventArgs e)
		{
			IP4Util.IP4namemapclass map = new IP4Util.IP4namemapclass();

			if (!IsValid(inmgrid))
			{
				MessageBox.Show("Resolve Validation Errors");
				return;
			}
			else
			{
				map = dgtable.tabletomap();
				if (map == null)		// if error transferring table due to duplicate IP4s, inform user and return to dialog		
				{
					MessageBox.Show("Duplicate IP4 addresses not allowed");
					return;
				}
				else        // else transfer local map to official map and close dialog
				{
                    changedsinceapplied = false;
					IP4Util.Instance.map = map;
                    GUIUtil.Instance.Hex = GUIUtil.Instance.Hex; // no-op but causes change notifications to gui
				}
			}
		}

        private void inmAccept(object sender, RoutedEventArgs e)
        // close window with saving changes
        {
            inmApply(this, null);
            Close();
        }

        private void inmCancel(object sender, RoutedEventArgs e)
        // close window without saving changes
		{
			Close();
		}

        private void inmcelleditending(object sender, DataGridCellEditEndingEventArgs e)
        // handle CellEditEnding event from the datagrid
        {
            changedsinceapplied = true;
            changedsincesavedtodisk = true;
        }

        private void inmSaveToDisk(object sender, RoutedEventArgs e)
		{
			SaveFileDialog dlg = new SaveFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();
			IP4Util.IP4namemapclass map = new IP4Util.IP4namemapclass();

			// first need to transfer datagrid table to official map
			if (!IsValid(inmgrid))
			{
				MessageBox.Show("Resolve Validation Errors.\nTable not saved.");
				return;
			}
			else
			{
				map = dgtable.tabletomap();
				if (map == null)		// if error transferring table due to duplicate IP4s, inform user and return to dialog		
				{
					MessageBox.Show("Duplicate IP4 addresses not allowed.\nTable not saved.");
					return;
				}
				else
				{
					dlg.InitialDirectory = "c:\\pviewer\\";
					dlg.DefaultExt = ".IP4namemap";
					dlg.OverwritePrompt = true;

					if (dlg.ShowDialog() == true)
					{
						fs = new FileStream(dlg.FileName, FileMode.OpenOrCreate);
						formatter.Serialize(fs, map);
                        changedsincesavedtodisk = false;
						fs.Close();
					}
				}
			}
		}

		private void inmLoadFromDisk(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			dlg.InitialDirectory = "c:\\pviewer\\";
			dlg.DefaultExt = ".IP4namemap";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					dgtable = ((IP4Util.IP4namemapclass)formatter.Deserialize(fs)).maptotable();
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					INMDG.ItemsSource = dgtable;
                    changedsincesavedtodisk = false;
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
		}
		private void inmAppendFromDisk(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			dlg.InitialDirectory = "c:\\pviewer\\";
			dlg.DefaultExt = ".IP4namemap";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					foreach (IP4Util.inmtableitem i in ((IP4Util.IP4namemapclass)formatter.Deserialize(fs)).maptotable()) dgtable.Add(i);
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					INMDG.ItemsSource = dgtable;
                    changedsincesavedtodisk = true;
				}
				catch
				{
					MessageBox.Show("File not read"); fs.Close(); return;
				}
				finally
				{
					fs.Close();
				}
			}
		}
		private static void Executedaddrow(object sender, ExecutedRoutedEventArgs e)
		{
			IP4Util.IP4nametableclass q;
			DataGrid dg = (DataGrid)e.Source;

			q = (IP4Util.IP4nametableclass)(dg.ItemsSource);

			q.Add(new IP4Util.inmtableitem(0, ""));
		}

		private static void PreviewExecutedaddrow(object sender, ExecutedRoutedEventArgs e)
		{
		}
		private static void CanExecuteaddrow(object sender, CanExecuteRoutedEventArgs e)
		{
			e.CanExecute = true;
		}


	}
}
