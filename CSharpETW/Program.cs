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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace CSharpETW
{
    using NTKeywords = KernelTraceEventParser.Keywords;

    class Analysis
    {
        public List<int> memoryData = new List<int>();

        public void StartAnalysis(CancellationToken ct)
        {
            
           
            while (!ct.IsCancellationRequested)
            {
                Process currentProcess = Process.GetCurrentProcess();
                int memoryUsed = (int)currentProcess.PrivateMemorySize64 / 1024/1024;
                Console.WriteLine(memoryUsed);
                // 將記憶體使用量存儲到數據數組中
                memoryData.Add(memoryUsed);

                // 每秒記錄一次，此處暫停1秒
                Thread.Sleep(1000);
            }
            
            
        }
    }
    public static class QueuedConsole
    {
        private static BlockingCollection<string> m_Queue = new BlockingCollection<string>();

        static QueuedConsole()
        {
            var thread = new Thread(() => { while (true) Console.WriteLine(m_Queue.Take()); });
            thread.IsBackground = true;
            thread.Start();
        }

        public static void WriteLine(string value)
        {
            m_Queue.Add(value);
        }
    }
    class ETWRecords
    {
        //obj.EventName, obj.ProcessID, obj.ProcessName, obj.KeyHandle, fullKeyName
        public string EventTime { get; set; }
        public string EventName { get; set; }
        public int ProcessID { get; set; }
        public string ProcessName { get; set; }
        public string ImagePath { get; set; }
        public string KeyHandle { get; set; }
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
        private static readonly double MonitorTimeInSeconds = 2;
        private static readonly int threadhold = 30;

        private static bool existed = false;
        private static object lockObject = new object();
        //MQ socket setting
        private PublisherSocket pubSocket;
        private static readonly int port = 5556;
        private static readonly string url = $"tcp://localhost:{port}";
        // system process filter
        private static readonly List<string> trustedList = new List<string>() { 
            "svchost",
            "System"
        };
        private static readonly List<string> trustedFolder = new List<string>()
        {
            Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32").Replace("\\","\\\\"),
            Environment.ExpandEnvironmentVariables(@"%SystemRoot%").Replace("\\","\\\\"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\MicroSoft Office").Replace("\\","\\\\")
        };
        private static readonly List<string> NontrustedProgram = new List<string>()
        {
            "reg",
            "powershell",
            "cmd"
        };
        private readonly List<string> _certList = new List<string>();
            
        private readonly static string userRegPath = @"HKEY_USERS\" + currentUserSid;
        // follow by MITRE: https://attack.mitre.org/techniques/T1547/001/
        // Note : need to replace HKEY_CURRENT_USER with HKEY_USERS\{user's SID}
        private readonly List<string> importantKey = new List<string>() {
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
        };
        private Timer timer;
        //private TraceEventSession session;

        public ETWTrace()
        {
            QueuedConsole.WriteLine("Publisher socket Binding...");
            this.pubSocket = new PublisherSocket();
            pubSocket.Bind(url);
            

        }
        public ETWTrace(List<string>certList)
        {
            QueuedConsole.WriteLine("Publisher socket Binding...");
            this.pubSocket = new PublisherSocket();
            pubSocket.Bind(url);
            _certList = certList;

        }
        public void SocketPublisher(ETWRecords records)
        {
            lock (lockObject)
            {

                QueuedConsole.WriteLine("Publisher socket Connecting...");

                pubSocket.Options.SendHighWatermark = 1000;
                
                string jsonData = JsonConvert.SerializeObject(records, Formatting.Indented);
                QueuedConsole.WriteLine(jsonData);
                pubSocket.SendMoreFrame("").SendFrame(jsonData);
                //Thread.Sleep(100);
                                     
            }
                    
        }

        public static X509Certificate2Collection GetFileCertificate(string filePath)
        {
            try
            {
                //X509Certificate2 cert = new X509Certificate2(filePath);
                //return cert;
                X509Certificate2Collection certificates = new X509Certificate2Collection();
                certificates.Import(filePath);
                return certificates;
            }
            catch (Exception)
            {
                // 發生例外情況，無法取得數位簽名
                return null;
            }
        }

        public bool KeyFilter(string keyPath)
        {

            return importantKey.Contains(keyPath, StringComparer.OrdinalIgnoreCase) ? true : false;
            
        }
        //whitelist
        public bool ProcessFilter(RegistryTraceData obj, string processPath)
        {
            /*
            if (processPath == null)
            {
                return obj.ProcessID != pid;
            }
            if (obj.ProcessName.Contains("powershell", StringComparison.OrdinalIgnoreCase) || obj.ProcessName.Contains("cmd", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            //test digital signed
            X509Certificate2Collection CertificateList = GetFileCertificate(processPath);
            
            bool flag = false;
            int count = 1;
            if (CertificateList != null)
            {

                foreach (X509Certificate2 signerCertificate in CertificateList)
                {
                    //Console.WriteLine($"{count}th Certificate");
                    count++;
                    
                    if (_certList.Contains(signerCertificate.Thumbprint))
                    {
                        
                        Console.WriteLine("Process digital certificate information:：");
                        Console.WriteLine("Signer： " + signerCertificate.Subject);
                        Console.WriteLine("Issuer： " + signerCertificate.Issuer);
                        Console.WriteLine("Deadline： " + signerCertificate.NotAfter);
                        Console.WriteLine("Thumbrprint： " + signerCertificate.Thumbprint);
                        Console.WriteLine();
                        flag = _certList.Contains(signerCertificate.Thumbprint);
                        signerCertificate.Dispose();
                    }
                    else
                    {
                        
                        Console.WriteLine("Not in Origin List");
                        Console.WriteLine("Process digital certificate information:：");
                        Console.WriteLine("Signer： " + signerCertificate.Subject);
                        Console.WriteLine("Issuer： " + signerCertificate.Issuer);
                        
                        foreach (StoreName storeName in (StoreName[])
                        Enum.GetValues(typeof(StoreName)))
                        {
                            if (storeName == StoreName.Disallowed)
                            {
                                continue;
                            }
                            X509Store store = new X509Store(storeName, StoreLocation.LocalMachine);
                            store.Open(OpenFlags.ReadOnly);
                            //test

                            X509Certificate2Collection issuer_certificates = store.Certificates.Find(
                            X509FindType.FindBySubjectDistinguishedName,
                            signerCertificate.Issuer,
                            false
                            );

                            foreach (X509Certificate2 x509 in issuer_certificates)
                            {
                                try
                                {
                                    //Console.WriteLine("Issuer Thumbrprint： " + x509.Thumbprint);

                                }
                                catch (CryptographicException)
                                {
                                    QueuedConsole.WriteLine("Information could not be written out for this certificate.");
                                }
                                flag = _certList.Contains(x509.Thumbprint);
                                
                                x509.Reset();
                                x509.Dispose();
                            }
                            store.Close();
                            store.Dispose();
                        }
                        signerCertificate.Dispose();
                        //Console.WriteLine("Deadline： " + signerCertificate.NotAfter);
                        //Console.WriteLine("Thumbrprint： " + signerCertificate.Thumbprint);
                        //Console.WriteLine();

                    }
                                        
                }
                
            }
            else
            {
                QueuedConsole.WriteLine("There is no signature in this process.");
                
            }
            CertificateList.Clear();
            return obj.ProcessID != pid && !flag;
            */
            //return obj.ProcessID == pid && !flag;
            
            if (obj.ProcessName.Equals("reg", StringComparison.OrdinalIgnoreCase)){
                Console.WriteLine("ss");
            }
            bool flag = false;
            foreach(string folder in trustedFolder)
            {
                
                if(Regex.IsMatch(processPath, folder, RegexOptions.IgnoreCase))
                {
                    flag = true;
                    break;
                }
            };


            //return obj.ProcessID!=pid && !trustedList.Contains(obj.ProcessName, StringComparer.OrdinalIgnoreCase);
            return obj.ProcessID != pid && !flag;
            //return obj.ProcessID != pid && !_certList.Contains(signerCertificate.Thumbprint);
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
            try
            {
                var stop = false;
                bool doOnce = true;
                QueuedConsole.WriteLine($"Starting rundown session: {sessionName}");
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
                                QueuedConsole.WriteLine("RunDown stop!!");
                                session.Stop();
                                session.Dispose();
                                stop = true;
                            });
                            doOnce = false;
                        }
                       
                        timer = new Timer(delegate (object state)
                        {
                            QueuedConsole.WriteLine("Timer crontab exec!!");
                            session.Stop();

                        }, null, (int)(MonitorTimeInSeconds * 1000), Timeout.Infinite);


                        session.Source.Process();

                    }

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred in RunDownSession: " + ex.ToString());
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

        //deprecated
        private void GeneralKeyCallBack(RegistryTraceData obj)
        {
            string processPath = null;
            if (!ProcessFilter(obj,processPath))
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

            object value = null;
            string composite_sz = null;
            RegistryKey regKey = null;
            RegistryValueKind rvk;
            Process process = null;
            string processPath = null;
            // key filter
            bool key_flag = KeyFilter(fullKeyName);
            
            try
            {              
                process = Process.GetProcessById(obj.ProcessID);
                processPath = process.MainModule.FileName;
                // filter
                if (!ProcessFilter(obj, processPath) && !key_flag)
                {
                    return;
                }              
            }
            catch(Exception ex)
            {
                QueuedConsole.WriteLine(ex.Message);
            }

            

            if (fullKeyName.Contains("HKEY_LOCAL_MACHINE"))
            {
                if (OperatingSystem.IsWindows())
                {
                    try 
                    {
                        regKey = Registry.LocalMachine.OpenSubKey(fullKeyName.Substring("HKEY_LOCAL_MACHINE".Length + 1));
                    }
                    catch(Exception ex)
                    {
                        QueuedConsole.WriteLine(ex.Message);
                    }
                    if (regKey != null)
                    {
                        try
                        {
                            rvk = regKey.GetValueKind(obj.ValueName);
                        }
                        catch (IOException)
                        {
                            // 處理值不存在的情況
                            QueuedConsole.WriteLine("Value does not exist.");
                            // 可以在這裡執行相應的操作或返回預設值
                            return;
                        }
                        if (rvk != RegistryValueKind.String && rvk != RegistryValueKind.ExpandString && rvk != RegistryValueKind.MultiString)
                        {
                            return;
                        }
                        value = regKey.GetValue(obj.ValueName);
                        if (value == null)
                        {
                            return;
                        }
                        if(rvk == RegistryValueKind.MultiString)
                        {
                            string[] valueArray = value as string[];
                            if (valueArray.Length == 0)
                            {
                                return;
                            }
                            foreach (string i in valueArray)
                            {
                                composite_sz += i;
                            }
                            value = composite_sz;
                        }
                        if (value.ToString().Length <= threadhold && !key_flag)
                        {
                            return;
                        }
                       
                        existed = true;
                        
                    }

                }
            }
            else if (fullKeyName.Contains("HKEY_USERS"))
            {
                if (OperatingSystem.IsWindows())
                {
                    try
                    {
                        regKey = Registry.Users.OpenSubKey(fullKeyName.Substring("HKEY_USERS".Length + 1));
                    }
                    catch (Exception ex)
                    {
                        QueuedConsole.WriteLine(ex.Message);
                    }
                    if (regKey != null)
                    {
                        try
                        {
                            rvk = regKey.GetValueKind(obj.ValueName);
                        }
                        catch (IOException)
                        {
                            // 處理值不存在的情況
                            QueuedConsole.WriteLine("Value does not exist.");
                            // 可以在這裡執行相應的操作或返回預設值
                            return;
                        }

                        if (rvk != RegistryValueKind.String && rvk != RegistryValueKind.ExpandString && rvk != RegistryValueKind.MultiString)
                        {
                            return;
                        }
                        value = regKey.GetValue(obj.ValueName);
                        if (value == null)
                        {
                            return;
                        }
                        if (rvk == RegistryValueKind.MultiString)
                        {
                            string[] valueArray = value as string[];
                            if (valueArray.Length == 0)
                            {
                                return;
                            }
                            foreach (string i in valueArray)
                            {
                                composite_sz += i;
                                composite_sz += ' ';
                            }
                            value = composite_sz;
                        }
                        if (value.ToString().Length <= threadhold && !key_flag)
                        {
                            return;
                        }
                      
                        existed = true;
                    }
                }
            }

            
            if (existed)
            {
                string formattedEventTime = obj.TimeStamp.ToString("yyyy/MM/dd HH:mm:ss");
                ETWRecords records = new ETWRecords(){ EventName=obj.EventName, EventTime=formattedEventTime ,ProcessID=obj.ProcessID, ProcessName=obj.ProcessName, ImagePath=processPath, KeyHandle="0x" + obj.KeyHandle.ToString("X"), FullKeyName=fullKeyName, ValueName=obj.ValueName, Value=value.ToString()};
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
            
            KeyHandle2KeyName.TryAdd(obj.KeyHandle, obj.KeyName);
            
            
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
                QueuedConsole.WriteLine("Please run me as Administrator!!");
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


                //Console.WriteLine(now.ToString("yyyy/MM/dd HH:mm:ss"));
                /*
                try
                {
                    await Task.Run(() => session.Source.Process());
                }
                catch (TaskCanceledException)
                {
                    Console.WriteLine("Session Cancelled!!");
                }
                */
                session.Source.Process();
                t1.Wait();
                QueuedConsole.WriteLine("Session Stop!!");

            }
            
        }

    }
    class Test
    {
        public Dictionary<int, string> options_value = new Dictionary<int, string>()
            {
                {1, new string('a', 31)},
                {2, @"Write-Host ""testing!!!"""},
                {3, @"powershell -executionpolicy bypass -windowstyle hidden -command ""$a = Get-ItemProperty -Path HKLM:\\System\\a | %{$_.v}; powershell -executionpolicy bypass -windowstyle hidden -encodedcommand $a"""},
                {4, @"powershell -executionpolicy bypass -windowstyle hidden -command ""$a = Get-ItemProperty -Path HKLM:\\System\\b | %{$_.v}; powershell -executionpolicy bypass -windowstyle hidden -encodedcommand $a"""}
            };

        public Dictionary<int, RegistryKey> options_key = new Dictionary<int, RegistryKey>();


        public int[] numbers = new int[5];
        public int[] numbers2 = new int[3];

        public Test()
        {
            if (OperatingSystem.IsWindows())
            {
                options_key[1] = Registry.LocalMachine.CreateSubKey(@"Software\RegistryKeyTest");
                options_key[2] = Registry.CurrentUser.CreateSubKey(@"AAAA\RegistryKeyTest");
            }
        }
        public void DoTesting()
        {
            Console.WriteLine("Test Start!!");
            if (OperatingSystem.IsWindows())
            {
                
                for (int i = 0; i < 200; i++)
                {
                    Thread.Sleep(3000);
                    Random crandom = new Random();
                    // random value
                    int choice_value = crandom.Next(1, 5);
                    numbers[choice_value]++;
                    
                    string chosenOption = options_value[choice_value];
                    // random key
                    int choice_key = crandom.Next(1, 3);
                    numbers2[choice_key]++;
                    options_key[choice_key].SetValue("Path", chosenOption);

                }
                for(int i = 1; i < numbers.Length; i++)
                {
                    Console.WriteLine($"Option{i}: {numbers[i]}");
                }

                Console.WriteLine("---------");

                for (int i = 1; i < numbers2.Length; i++)
                {
                    Console.WriteLine($"Option{i}: {numbers2[i]}");
                }
            }
            Console.WriteLine("Stop");
            Console.ReadLine();
        }
        //do reg_muti_sz
        public void DoTesting2()
        {

        }
        //Important key test
        public void DoTesting3()
        {

        }


    }
    class Program
    {
        static void Main(string[] args)
        {
           
                      
            using (CancellationTokenSource cts = new CancellationTokenSource()){

                // Store Thumbprint of MicroSoft 
                /*
                List<string> certList = new List<string>();
                QueuedConsole.WriteLine("Certificate published by MicroSoft : ");
                foreach (StoreName storeName in (StoreName[])
                        Enum.GetValues(typeof(StoreName)))
                {

                    if (storeName == StoreName.Disallowed)
                    {
                        continue;
                    }

                    X509Store store = new X509Store(storeName, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.OpenExistingOnly);

                    // 獲取存放區中的所有憑證
                    X509Certificate2Collection certificates = store.Certificates;


                    foreach (X509Certificate2 cert in certificates)
                    {
                        if (cert.Subject.Contains("Microsoft"))
                        {
                            // 檢查憑證的發行者是否包含 "Microsoft" 字樣

                            QueuedConsole.WriteLine("Process digital certificate information:：");
                            QueuedConsole.WriteLine("Signer： " + cert.Subject);
                            QueuedConsole.WriteLine("Issuer： " + cert.Issuer);
                            QueuedConsole.WriteLine("Deadline： " + cert.NotAfter);
                            QueuedConsole.WriteLine("Thumbrprint： " + cert.Thumbprint);
                            certList.Add(cert.Thumbprint);
                        }

                    }
                }
                */

                if (OperatingSystem.IsWindows())
                {
                    string currentUserSid = WindowsIdentity.GetCurrent().User.Value;
                    QueuedConsole.WriteLine("Current user SID: " + currentUserSid);
                }
                Console.CancelKeyPress += (sender, eventArgs) =>
                {
                    QueuedConsole.WriteLine("Cancel Session");
                    cts.Cancel();
                    eventArgs.Cancel = true;

                };

                ETWTrace trace = new ETWTrace();

                Task task = Task.Run(()=> trace.StartSession(cts.Token),cts.Token);
                Thread.Sleep(1000);


                //Stopwatch stopwatch = new Stopwatch();
                //stopwatch.Start();
                //Analysis As = new Analysis();
                //Task as_task = Task.Run(() => As.StartAnalysis(cts.Token), cts.Token);
                
                /*do Testing here*/
                //Test test = new Test();
                //Task test_task = Task.Run(() => test.DoTesting(), cts.Token);
                
                task.Wait();
                /*
                as_task.Wait();
                stopwatch.Stop();
                long sum = 0;
                foreach(int i in As.memoryData)
                {
                    sum += i;
                }
                Console.WriteLine($"{stopwatch.Elapsed.TotalSeconds}");
                Console.WriteLine($"average mem : {(double)(sum / stopwatch.Elapsed.TotalSeconds)}");
                */
                if (OperatingSystem.IsWindows())
                {
                    var registryKey = Registry.LocalMachine.OpenSubKey(@"Software\RegistryKeyTest");
                    var registryKey2 = Registry.CurrentUser.OpenSubKey(@"AAAA");

                    if(registryKey!=null && registryKey2 != null)
                    {
                        Registry.LocalMachine.DeleteSubKey(@"Software\RegistryKeyTest");
                        Registry.CurrentUser.DeleteSubKeyTree(@"AAAA");
                    }

                    cts.Cancel();
                }
                

            }
           
            
        }
    }

     
}
