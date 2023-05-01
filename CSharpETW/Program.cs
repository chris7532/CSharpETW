using System;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.IO;
using Newtonsoft.Json;
using NetMQ;
using NetMQ.Sockets;


namespace CSharpETW
{
    using NTKeywords = KernelTraceEventParser.Keywords;
    class ETWRecords
    {
        //obj.EventName, obj.ProcessID, obj.ProcessName, obj.KeyHandle, fullKeyName
        public string EventName { get; set; }
        public int ProcessID { get; set; }
        public string ProcessName { get; set; }
        public string ImagePath { get; set; }
        public ulong KeyHandle { get; set; }
        public string FullKeyName { get; set; }
        public string ValueName { get; set; }
        public string Value { get; set; }
    
    }

    class ETWTrace
    {
        private static Dictionary<UInt64, String> KeyHandle2KeyName = new Dictionary<UInt64, String>() { };
        // user info
        private static readonly string currentUserSid = OperatingSystem.IsWindows() ? WindowsIdentity.GetCurrent().User.Value : null;
        private static readonly int pid = Process.GetCurrentProcess().Id;
        //Config setting
        private static readonly double MonitorTimeInSeconds = 1;
        private static readonly int threadhold = 30;

        private static bool existed = false;
        private static object lockObject = new object();
        //MQ socket setting
        private PublisherSocket pubSocket;
        private static readonly int port = 5556;
        private static readonly string url = $"tcp://localhost:{port}";
        // system process filter
        private static readonly List<string> blackList = new List<string>() { 
            "svchost"
        };
        private readonly static string userRegPath = @"HKEY_USERS\" + currentUserSid;
        // follow by MITRE: https://attack.mitre.org/techniques/T1547/001/
        // Note : need to replace HKEY_CURRENT_USER with HKEY_USERS\{user's SID}
        private static readonly List<string> importantKey = new List<string>() {
            userRegPath + @"\Software\Microsoft\Windows\CurrentVersion\Run",
            userRegPath + @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
             userRegPath + @"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
             userRegPath + @"\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
             userRegPath + @"\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",
             userRegPath + @"\Software\Microsoft\Windows\CurrentVersion\RunServices",
            @"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
             userRegPath + @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
             userRegPath + @"\AAAA\RegistryKeyTest"
        };
        public ETWTrace()
        {
            Console.WriteLine("Publisher socket Binding...");
            this.pubSocket = new PublisherSocket();
            pubSocket.Bind(url);

        }
        public void SocketPublisher(ETWRecords records)
        {
            lock (lockObject)
            {
               
                Console.WriteLine("Publisher socket Connecting...");

                pubSocket.Options.SendHighWatermark = 1000;
                
                string jsonData = JsonConvert.SerializeObject(records);
                Console.WriteLine(jsonData);
                pubSocket.SendMoreFrame("").SendFrame(jsonData);
                //Thread.Sleep(100);
                                     
            }
                    
        }
        public bool KeyFilter(string keyPath)
        {
            return importantKey.Contains(keyPath) ? true : false;
            
        }
        //whitelist
        public bool ProcessFilter(RegistryTraceData obj)
        {
            return obj.ProcessID == pid;
            //return obj.ProcessID!=pid && !blackList.Contains(obj.ProcessName);
        }

        public void MakeKernelParserStateless(ETWTraceEventSource source)
        {
            var options = KernelTraceEventParser.ParserTrackingOptions.None;
            var kernelParser = new KernelTraceEventParser(source,options);
            var t = source.GetType();
            var kernelField = t.GetField("_Kernel", BindingFlags.Instance | BindingFlags.SetField | BindingFlags.NonPublic);
            kernelField.SetValue(source, kernelParser);
        }
        public void RunDownSession(String sessionName, CancellationToken token)
        {
            var stop = false;
            bool doOnce = true;
            Console.WriteLine("Starting rundown session: {0}", sessionName);
            while (!stop)
            {
                
                using (TraceEventSession session = new TraceEventSession(sessionName))
                {
                    session.EnableKernelProvider(NTKeywords.Registry, NTKeywords.None);

                    MakeKernelParserStateless(session.Source);
                    session.Source.Kernel.RegistryKCBRundownBegin += KCBCreate;
                    session.Source.Kernel.RegistryKCBRundownEnd += KCBCreate;

                    if (doOnce)
                    {
                        token.Register(() =>
                        {
                            Console.WriteLine("RunDown stop!!");
                            session.Stop();
                            session.Dispose();
                            stop = true;
                        });
                        doOnce = false;
                    }
                    
                    var timer = new Timer(delegate (object state)
                    {
                        Console.WriteLine("Timer crontab exec!!");
                        session.Stop();
                    }, null, (int)(MonitorTimeInSeconds * 1000), Timeout.Infinite);

                    session.Source.Process();

                }
                                         
            }
        }
        public String GetFullName(UInt64 keyHandle, String keyName)
        {
            var baseKeyName = KeyHandle2KeyName.ContainsKey(keyHandle) ? KeyHandle2KeyName[keyHandle] : "";
            var CombineName = Path.Combine(baseKeyName, keyName);
            CombineName = Regex.Replace(CombineName, @"\\REGISTRY\\MACHINE", "HKEY_LOCAL_MACHINE", RegexOptions.IgnoreCase);
            CombineName = Regex.Replace(CombineName, @"\\REGISTRY\\USER", "HKEY_USERS", RegexOptions.IgnoreCase);

            return CombineName;
        }

        private void GeneralKeyCallBack(RegistryTraceData obj)
        {
            if (!ProcessFilter(obj))
            {
                return;
            }

            var fullKeyName = GetFullName(obj.KeyHandle, obj.KeyName);
            Console.WriteLine(
            "EventName:{0} \t PID: {1} \t ProcessName: {2} \t KeyHandle: 0x{3:X} \t KeyName: {4}",
            obj.EventName, obj.ProcessID, obj.ProcessName, obj.KeyHandle, fullKeyName
            );         
        }
        private void GeneralValueCallBack(RegistryTraceData obj)
        {
            var fullKeyName = GetFullName(obj.KeyHandle, obj.KeyName);

            // testing filter
            if (!ProcessFilter(obj) || !KeyFilter(fullKeyName))
            {
                return;
            }

            /*
            if(!ProcessFilter(obj) && !KeyFilter(fullKeyName))
            {
                return;
            }
            */
            object value = null;
            
            RegistryKey regKey = null;
            RegistryValueKind rvk;

            if (fullKeyName.Contains("HKEY_LOCAL_MACHINE"))
            {
                if (OperatingSystem.IsWindows())
                {
                    regKey = Registry.LocalMachine.OpenSubKey(fullKeyName.Substring("HKEY_LOCAL_MACHINE".Length + 1));
                    if (regKey != null)
                    {
                        rvk = regKey.GetValueKind(obj.ValueName);
                        if (rvk != RegistryValueKind.String && rvk != RegistryValueKind.ExpandString && rvk != RegistryValueKind.MultiString)
                        {
                            return;
                        }
                        value = regKey.GetValue(obj.ValueName);
                        if (value.ToString().Length <= threadhold)
                        {
                            return;
                        }
                        if (value != null)
                        {
                            Console.WriteLine("Find Value !!");
                            existed = true;
                        }
                    }

                }
            }
            else if (fullKeyName.Contains("HKEY_USERS"))
            {
                if (OperatingSystem.IsWindows())
                {
                    regKey = Registry.Users.OpenSubKey(fullKeyName.Substring("HKEY_USERS".Length + 1));
                    if (regKey != null)
                    {
                        rvk = regKey.GetValueKind(obj.ValueName);
                        if (rvk != RegistryValueKind.String && rvk != RegistryValueKind.ExpandString && rvk != RegistryValueKind.MultiString)
                        {
                            return;
                        }
                        value = regKey.GetValue(obj.ValueName);             
                        if (value.ToString().Length <= threadhold)
                        {
                            return;
                        }
                        if (value != null)
                        {

                            Console.WriteLine("Find Value !!");
                            existed = true;
                        }
                    }
                }
            }


            if (existed)
            {
                Process process = Process.GetProcessById(obj.ProcessID);
                string processPath = process.MainModule.FileName;
                ETWRecords records = new ETWRecords(){ EventName=obj.EventName, ProcessID=obj.ProcessID, ProcessName=obj.ProcessName, ImagePath=processPath, KeyHandle=obj.KeyHandle, FullKeyName=fullKeyName, ValueName=obj.ValueName, Value=value.ToString()};
                SocketPublisher(records);
                existed = false;
            }
            /*
            Console.WriteLine(
            "EventName:{0} \t PID: {1} \t ProcessName: {2} \t KeyHandle: 0x{3:X} \t KeyName: {4}",
            obj.EventName, obj.ProcessID, obj.ProcessName, obj.KeyHandle, fullKeyName
            );*/

        }

        private void KCBCreate(RegistryTraceData obj)
        {
            /*
            Console.WriteLine(
              "EventName:{0} \t KeyHandle: 0x{1:X} \t KeyName: {2} \t ProcessName: {3}",
              obj.EventName, obj.KeyHandle, obj.KeyName, obj.ProcessName
              );
            */
            if (KeyHandle2KeyName.ContainsKey(obj.KeyHandle)){
                KeyHandle2KeyName[obj.KeyHandle] = obj.KeyName;
            }
            else
            {
                KeyHandle2KeyName.Add(obj.KeyHandle, obj.KeyName);
            }
            
        }
        private void KCBDelete(RegistryTraceData obj)
        {
            /*
            Console.WriteLine(
                "EventName:{0} \t KeyHandle: 0x{1:X} \t KeyName: {2}",
                obj.EventName, obj.KeyHandle, obj.KeyName
                );
            */
            KeyHandle2KeyName.Remove(obj.KeyHandle);
        }

        public void StartSession(CancellationToken token)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("Please run me as Administrator!!");
                return;
            }
                      
            var sessionName = "My_Reg_Trace";
            using (TraceEventSession session = new TraceEventSession(sessionName))
            {
                session.EnableKernelProvider(
                    NTKeywords.Registry,
                    NTKeywords.None
                    );

                MakeKernelParserStateless(session.Source);
                Task t1 =  Task.Run(()=>RunDownSession(sessionName + "_RunDown", token));

                session.Source.Kernel.RegistryKCBCreate += KCBCreate;
                session.Source.Kernel.RegistryKCBDelete += KCBDelete;
                //session.Source.Kernel.RegistryOpen += GeneralKeyCallBack;
                session.Source.Kernel.RegistrySetValue += GeneralValueCallBack;

                token.Register(() => {
                    session.Stop();
                    Console.WriteLine("Publisher socket Disconnecting...");
                    pubSocket.Dispose();
                    });
                
                session.Source.Process();
                t1.Wait();
                Console.WriteLine("Session Stop!!");

            }
            
        }
    }
    
    class Program
    {

        static void Main(string[] args)
        {

            using (CancellationTokenSource cts = new CancellationTokenSource()){

                if (OperatingSystem.IsWindows())
                {
                    string currentUserSid = WindowsIdentity.GetCurrent().User.Value;
                    Console.WriteLine("Current user SID: " + currentUserSid);
                }
                Console.CancelKeyPress += (sender, eventArgs) =>
                {
                    Console.WriteLine("Cancel Session");
                    cts.Cancel();
                    eventArgs.Cancel = true;

                };

                ETWTrace trace = new ETWTrace();

                Task task = Task.Run(()=> trace.StartSession(cts.Token),cts.Token);

                Thread.Sleep(1000);

                /*do Testing here*/
                Console.WriteLine("Test Start!!");
                if (OperatingSystem.IsWindows())
                {
                    Console.WriteLine("Write Key");
                    RegistryKey registryKey = Registry.CurrentUser.CreateSubKey(@"AAAB\RegistryKeyTest");
                    
                    registryKey.SetValue("Path", @"powershell -executionpolicy bypass -windowstyle hidden -command ""$a = Get-ItemProperty -Path HKLM:\\System\\a | %{$_.v}; powershell -executionpolicy bypass -windowstyle hidden -encodedcommand $a""");
                }
                task.Wait();
                if (OperatingSystem.IsWindows())
                {
                    //Registry.ClassesRoot.DeleteSubKeyTree(@"AAAA\RegistryKeyTest");
                    Registry.CurrentUser.DeleteSubKeyTree(@"AAAB");
                    cts.Cancel();
                }
                

            }
           
            
        }
    }

     
}
