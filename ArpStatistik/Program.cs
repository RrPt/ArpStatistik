using System;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using SharpPcap.WinPcap;
using PacketDotNet;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.IO;
using System.Runtime.InteropServices;

namespace ArpStatistik
{
    class MainClass
    {
        private static CaptureFileWriterDevice captureFileWriter;
        private static Dictionary<IPAddress, PhysicalAddress> list = new Dictionary<IPAddress, PhysicalAddress>();
        private static int packetIndex = 0;
        private static long scanDelay = 1000000;  // in us
        static LibPcapLiveDevice device;

        public static void Main(string[] args)
        {
            string netz = null;

            if (args.Length < 1)
            {
                Console.WriteLine("Subnetz nicht angegeben --> automatische Auswahl");
                netz = GetNetz();
                if (netz == null) { Console.WriteLine("keine passendes Netzwerk gefunden"); return; }
            }
            else
            {
                netz = args[0];
            }
            if (!netz.EndsWith(".")) netz += ".";
            string testIp = netz + "1";
            IPAddress ip;
            if (!IPAddress.TryParse(testIp, out ip)) { Console.WriteLine("kein gültiges Subnetz angegeben " + netz); return; }
            device = GetDevice(netz);
            if (device == null) { Console.WriteLine("keine Netzwerkkarte im Subnetz " + netz); return; }

            bool end = false;
            while (!end)
            {
                //StartPcapSniffer();
                ActivePollMacs(netz);

                // 30s warten
                Console.WriteLine("q zum beenden");
                for (int i = 0; i < 30; i++)
                {
                    System.Threading.Thread.Sleep(1000);
                    if (Console.KeyAvailable)
                    {
                        var k = Console.ReadKey();
                        if (k.KeyChar.Equals('q')) return;
                    }
                }
            }
        }


        private static void ActivePollMacs(string subnet)
        {
            if (subnet == null) return;
            for (int i = 1; i < 255; i++)
            {
                IPAddress ip = IPAddress.Parse(subnet + i);
                string macStr = GetMacFromIp(ip);
                PhysicalAddress mac = null;
                if (macStr.Length == 12)
                {
                    Console.WriteLine("{0:yyMMdd HH:mm:ss}: {1,-15} {2}", DateTime.Now, ip.ToString(), macStr);
                    mac = PhysicalAddress.Parse(macStr);
                }
                if (mac != null) CheckZuordnung(mac, ip,subnet);
            }
        }


        private static string GetMacFromIp(IPAddress targetIP)
        {
            // Create a new ARP resolver
            ARP arp = new ARP(device);
            arp.Timeout = new System.TimeSpan(scanDelay);

            // Enviar ARP
            var resolvedMacAddress = arp.Resolve(targetIP);

            if (resolvedMacAddress == null)
            {
                return "fail";
            }
            else
            {
                string fmac = resolvedMacAddress.ToString(); // formatMac(resolvedMacAddress);
                //Console.WriteLine(targetIP + " is at: " + fmac);

                return fmac;
            }

        }



        #region dll
        private static string GetMacFromIpDll(IPAddress dst)
        {
            // Please do not use the IPAddress.Address property
            // This API is now obsolete. --> http://msdn.microsoft.com/en-us/library/system.net.ipaddress.address.aspx
            // to get the IP in Integer mode use

            uint uintAddress = BitConverter.ToUInt32(dst.GetAddressBytes(), 0);
            byte[] macAddr = new byte[6];
            int macAddrLen = macAddr.Length;
            int retValue = SendARP(uintAddress, 0, macAddr, ref macAddrLen);
            if (retValue != 0)
            {
                //throw new Exception("SendARP failed. ret=" + retValue);
                return "";
            }

            string[] str = new string[(int)macAddrLen];
            for (int i = 0; i < macAddrLen; i++)
                str[i] = macAddr[i].ToString("x2");

            //Console.WriteLine(string.Join(":", str));
            return string.Join(":", str);
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

        #endregion

        static public LibPcapLiveDevice GetDevice(string netz)
        {
            LibPcapLiveDevice selectedDevice = null;
            // Retrieve the device list
            var devices = LibPcapLiveDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return null;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on Subnet " + netz);
            Console.WriteLine("---------------------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the devices
            foreach (var dev in devices)
            {
                dev.Open();
                foreach (var adr in dev.Addresses)
                {
                    IPAddress ip = adr.Addr.ipAddress;
                    if (ip != null)
                    {
                        string ipStr = ip.ToString();
                        if (ipStr.Contains(netz))
                        {
                            Console.WriteLine("{0}) {1} {2} {3}", i, ipStr, dev.Name, dev.Description);
                            selectedDevice = dev;
                            i++;
                        }
                    }
                }

                /* Description */
                //i++;
                dev.Close();
            }

            if (i == 0) Console.WriteLine("Kein Device im passenden Subnetz gefunden");
            if (i == 1) Console.WriteLine("Device automatisch gewählt");
            if (i == 2) Console.WriteLine("mehrere Device im passenden Subnetz gefunden. letztes gewählt");

            Console.WriteLine();

            return selectedDevice;
        }

        static public string GetNetz()
        {
            string netz = null;
            List<string> netList = new List<string>();

            LibPcapLiveDevice selectedDevice = null;
            // Retrieve the device list
            var devices = LibPcapLiveDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return null;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on Subnet ");
            Console.WriteLine("---------------------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the devices
            foreach (var dev in devices)
            {
                dev.Open();
                foreach (var adr in dev.Addresses)
                {
                    IPAddress ip = adr.Addr.ipAddress;
                    if (ip != null)
                    {
                        string ipStr = ip.ToString();
                        if ((ipStr.StartsWith("192.168.")) || (ipStr.StartsWith("10.")))
                        {
                            Console.WriteLine("{0}) {1} {2} {3}", i, ipStr, dev.Name, dev.Description);

                            netz = ip.ToString();
                            netz = netz.Substring(0, netz.LastIndexOf("."));
                            netList.Add(netz);
                            i++;

                        }
                    }
                }

                /* Description */
                //i++;
                dev.Close();
            }

            if (i == 0) Console.WriteLine("Kein passendes Subnetz gefunden");
            if (i == 1) Console.WriteLine("Subnetz automatisch gewählt: " + netz);
            if (i >= 2)
            {
                Console.WriteLine("mehrere Subnetze gefunden. bitte auswäklen  0.." + (i - 1));
                int select = int.Parse(Console.ReadLine());

                netz = netList[select];
            }


            return netz;
        }


        private static void StartPcapSniffer()
        {
            // Print SharpPcap version
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap {0}, ArpStatistik", ver);

            //// Retrieve the device list
            //var devices = LibPcapLiveDeviceList.Instance;

            //// If no devices were found print an error
            //if (devices.Count < 1)
            //{
            //    Console.WriteLine("No devices were found on this machine");
            //    return;
            //}

            //Console.WriteLine();
            //Console.WriteLine("The following devices are available on this machine:");
            //Console.WriteLine("----------------------------------------------------");
            //Console.WriteLine();

            //int i = 0;

            //// Print out the devices
            //foreach (var dev in devices)
            //{
            //    /* Description */
            //    Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
            //    i++;
            //}

            //Console.WriteLine();
            //Console.Write("-- Please choose a device to capture on: ");
            //i = int.Parse(Console.ReadLine());
            ////i = 2;
            //Console.Write("-- Please enter the output file name: ");
            ////string capFile = Console.ReadLine();
            string capFile = "test.pcap";

            //var device = devices[i];

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            if (device is AirPcapDevice)
            {
                // NOTE: AirPcap devices cannot disable local capture
                var airPcap = device as AirPcapDevice;
                airPcap.Open(SharpPcap.WinPcap.OpenFlags.DataTransferUdp, readTimeoutMilliseconds);
            }
            else if (device is WinPcapDevice)
            {
                var winPcap = device as WinPcapDevice;
                winPcap.Open(SharpPcap.WinPcap.OpenFlags.DataTransferUdp | SharpPcap.WinPcap.OpenFlags.NoCaptureLocal, readTimeoutMilliseconds);
            }
            else if (device is LibPcapLiveDevice)
            {
                var livePcapDevice = device as LibPcapLiveDevice;
                livePcapDevice.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            }
            else
            {
                throw new System.InvalidOperationException("unknown device type of " + device.GetType().ToString());
            }

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, writing to {2}, hit 'Enter' to stop...",
                              device.Name, device.Description,
                              capFile);

            // open the output file
            captureFileWriter = new CaptureFileWriterDevice(device, capFile);

            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

            Console.WriteLine("-- Capture stopped.");

            // Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());

            // Close the pcap device
            device.Close();
        }


        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            //var device = (ICaptureDevice)sender;

            // write the packet to the file
            //captureFileWriter.Write(e.Packet);
            //Console.WriteLine("Packet dumped to file.");

            if (e.Packet.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
            {
                var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ethernetPacket = (PacketDotNet.EthernetPacket)packet;

                if (ethernetPacket.Type == EthernetPacketType.Arp)
                {
                    ARPPacket arp = (ARPPacket)ethernetPacket.PayloadPacket;

                    //if (arp.Operation == ARPOperation.Request) return;

                    captureFileWriter.Write(e.Packet);
                    if (arp.Operation == ARPOperation.Response) Console.ForegroundColor = ConsoleColor.Yellow;
                    else Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine("{0} At: {1}:{2,3}: MAC:{3} -> MAC:{4}  {5} {6,8} {7} {8,15} --> {9} {10,15}",
                                      packetIndex,
                                      e.Packet.Timeval.Date.ToString(),
                                      e.Packet.Timeval.Date.Millisecond,
                                      ethernetPacket.SourceHwAddress,
                                      ethernetPacket.DestinationHwAddress,
                                      ethernetPacket.Type,
                                      arp.Operation,
                                      arp.SenderHardwareAddress,
                                      arp.SenderProtocolAddress,
                                      arp.TargetHardwareAddress,
                                      arp.TargetProtocolAddress
                                      );
                    CheckZuordnung(arp.SenderHardwareAddress, arp.SenderProtocolAddress);
                    if (arp.Operation == ARPOperation.Response) CheckZuordnung(arp.TargetHardwareAddress, arp.TargetProtocolAddress);



                    packetIndex++;
                }
            }
        }

        private static void CheckZuordnung(PhysicalAddress mac, IPAddress ip,string subnet = "noNet")
        {
            string path = @"log\" + subnet + @"\";
            if (!Directory.Exists(path)) Directory.CreateDirectory(path);

            if (!list.ContainsKey(ip))
            {
                list.Add(ip, mac);
                File.AppendAllText(path + ip + ".txt", DateTime.Now + " " + mac + Environment.NewLine);
            }
            else if (!list[ip].Equals(mac))
            {
                list[ip] = mac;
                File.AppendAllText(path + ip + ".txt", DateTime.Now + " " + mac + "  *" + Environment.NewLine);
                File.AppendAllText(path + @"MultipleMacs.txt", DateTime.Now + " " + ip + " " + mac + Environment.NewLine);
            }
        }
    }
}
