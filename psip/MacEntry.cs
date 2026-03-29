using System.ComponentModel;

namespace psip
{
    public class MacEntry : INotifyPropertyChanged
    {
        private string _macAddress;
        private int _portNumber;
        private int _agingTime;

        public string MacAddress
        {
            get => _macAddress;
            set
            {
                if (_macAddress != value)
                {
                    _macAddress = value;
                    OnPropertyChanged(nameof(MacAddress));
                }
            }
        }

        public int PortNumber
        {
            get => _portNumber;
            set
            {
                if (_portNumber != value)
                {
                    _portNumber = value;
                    OnPropertyChanged(nameof(PortNumber));
                }
            }
        }

        public int AgingTime
        {
            get => _agingTime;
            set
            {
                if (_agingTime != value)
                {
                    _agingTime = value;
                    OnPropertyChanged(nameof(AgingTime));
                }
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}