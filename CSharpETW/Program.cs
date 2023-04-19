using System;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.IO;


namespace CSharpETW
{
    using NTKeywords = KernelTraceEventParser.Keywords;
    
    class ETWTrace
    {
        private static Dictionary<UInt64, String> KeyHandle2KeyName = new Dictionary<UInt64, String>() { };
        public static int pid = Process.GetCurrentProcess().Id;
        public double MonitorTimeInSeconds = 1;
        //public ETWTrace instnace = new ETWTrace();
        public static Boolean ProcessFilter(RegistryTraceData obj)
        {
            return obj.ProcessID!=pid;
        }

        public static void MakeKernelParserStateless(ETWTraceEventSource source)
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
            Console.WriteLine("Starting rundown session: {0}", sessionName);
            while (!stop)
            {
                using (TraceEventSession session = new TraceEventSession(sessionName))
                {
                    session.EnableKernelProvider(NTKeywords.Registry, NTKeywords.None);

                    MakeKernelParserStateless(session.Source);
                    session.Source.Kernel.RegistryKCBRundownBegin += KCBCreate;
                    session.Source.Kernel.RegistryKCBRundownEnd += KCBCreate;

                    /*CancellationTokenSource cts = new CancellationTokenSource();

                    _ = cts.Token.Register(() =>
                    {
                        session.Stop();
                    });*/
                    token.Register(() =>
                    {
                        Console.WriteLine("RunDown stop!!");
                        session.Stop();
                        session.Dispose();
                        stop = true;
                    });
                    var timer = new Timer(delegate (object state)
                    {
                        Console.WriteLine("Timer crontab exec!!");
                        session.Stop();
                    }, null, (int)(MonitorTimeInSeconds * 1000), Timeout.Infinite);

                    session.Source.Process();

                }
                         
            }
        }
        public static String GetFullName(UInt64 keyHandle, String keyName)
        {
            var baseKeyName = KeyHandle2KeyName.ContainsKey(keyHandle) ? KeyHandle2KeyName[keyHandle] : "";
            var CombineName = Path.Combine(baseKeyName, keyName);
            CombineName = Regex.Replace(CombineName, @"\\REGISTRY\\MACHINE", "HKEY_LOCAL_MACHINE", RegexOptions.IgnoreCase);
            CombineName = Regex.Replace(CombineName, @"\\REGISTRY\\USER", "HKEY_USERS", RegexOptions.IgnoreCase);

            return CombineName;
        }


        private static void GeneralKeyCallBack(RegistryTraceData obj)
        {
            if (ProcessFilter(obj))
            {
                var fullKeyName = GetFullName(obj.KeyHandle, obj.KeyName);
                Console.WriteLine(
                "EventName:{0} \t PID: {1} \t ProcessName: {2} \t KeyHandle: 0x{3:X} \t KeyName: {4}",
                obj.EventName, obj.ProcessID, obj.ProcessName, obj.KeyHandle, fullKeyName
                );
            }
            
        }
        private static void GeneralValueCallBack(RegistryTraceData obj)
        {

            if (ProcessFilter(obj))
            {
                var fullKeyName = GetFullName(obj.KeyHandle, obj.KeyName);

                if (fullKeyName.Contains("HKEY_CLASSES_ROOT"))
                {
                    if (OperatingSystem.IsWindows())
                    {
                        RegistryKey regKey = Registry.ClassesRoot.OpenSubKey(fullKeyName.Substring("HKEY_CLASSES_ROOT".Length + 1));
                        if (regKey != null)
                        {
                            var res = regKey.GetValue(obj.ValueName);
                            if (res != null)
                            {
                                Console.WriteLine("Find Value !!");
                            }


                        }
                    }
                }
                else if (fullKeyName.Contains("HKEY_CURRENT_USER"))
                {
                    if (OperatingSystem.IsWindows())
                    {
                        RegistryKey regKey = Registry.CurrentUser.OpenSubKey(fullKeyName.Substring("HKEY_CURRENT_USER".Length + 1));
                        if (regKey != null)
                        {
                            var res = regKey.GetValue(obj.ValueName);
                            if (res != null)
                            {
                                Console.WriteLine("Find Value !!");
                            }
                        }
                    }
                }
                else if (fullKeyName.Contains("HKEY_LOCAL_MACHINE"))
                {
                    if (OperatingSystem.IsWindows())
                    {
                        RegistryKey regKey = Registry.LocalMachine.OpenSubKey(fullKeyName.Substring("HKEY_LOCAL_MACHINE".Length + 1));
                        if (regKey != null)
                        {
                            var res = regKey.GetValue(obj.ValueName);
                            if (res != null)
                            {
                                Console.WriteLine("Find Value !!");
                            }
                        }

                    }
                }
                else if (fullKeyName.Contains("HKEY_USERS"))
                {
                    if (OperatingSystem.IsWindows())
                    {
                        RegistryKey regKey = Registry.Users.OpenSubKey(fullKeyName.Substring("HKEY_USERS".Length + 1));
                        if (regKey != null)
                        {
                            var res = regKey.GetValue(obj.ValueName);
                            if (res != null)
                            {
                                Console.WriteLine("Find Value !!");
                            }
                        }
                    }
                }
                else if (fullKeyName.Contains("HKEY_CURRENT_CONFIG"))
                {
                    if (OperatingSystem.IsWindows())
                    {
                        RegistryKey regKey = Registry.CurrentConfig.OpenSubKey(fullKeyName.Substring("HKEY_CURRENT_CONFIG".Length + 1));
                        if (regKey != null)
                        {
                            var res = regKey.GetValue(obj.ValueName);
                            if (res != null)
                            {
                                Console.WriteLine("Find Value !!");
                            }
                        }
                    }
                }
                  
                Console.WriteLine(
                "EventName:{0} \t PID: {1} \t ProcessName: {2} \t KeyHandle: 0x{3:X} \t KeyName: {4}",
                obj.EventName, obj.ProcessID, obj.ProcessName, obj.KeyHandle, fullKeyName
                );
                
            }
        }
        private static void KCBCreate(RegistryTraceData obj)
        {
            /*
            Console.WriteLine(
                "EventName:{0} \t KeyHandle: 0x{1:X} \t KeyName: {2}",
                obj.EventName, obj.KeyHandle, obj.KeyName
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
        private static void KCBDelete(RegistryTraceData obj)
        {
            Console.WriteLine(
                "EventName:{0} \t KeyHandle: 0x{1:X} \t KeyName: {2}",
                obj.EventName, obj.KeyHandle, obj.KeyName
                );
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
                Thread t1 = new Thread(new ThreadStart(()=> RunDownSession(sessionName + "_RunDown", token)));
                t1.Start();
                //RunDownSession(sessionName + "_RunDown",token);

                session.Source.Kernel.RegistryKCBCreate += KCBCreate;
                session.Source.Kernel.RegistryKCBDelete += KCBDelete;
                //session.Source.Kernel.RegistryOpen += GeneralKeyCallBack;
                session.Source.Kernel.RegistrySetValue += GeneralValueCallBack;

                token.Register(() => {
                    session.Stop();
                    });
                /*
                var timer = new Timer(delegate (object state)
                {
                    Console.WriteLine("Timer crontab exec!");
                    session.Stop();
                }, null, (int)(MonitorTimeInSeconds * 1000), Timeout.Infinite);
                */
                session.Source.Process();

                Console.WriteLine("Session Stop!!");
                //session.Stop();
                //session.Dispose();
            }
            
        }
    }
    class Program
    {

        static void Main(string[] args)
        {

            CancellationTokenSource cts = new CancellationTokenSource();
            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                Console.WriteLine("Cancel Session");
                cts.Cancel();
                eventArgs.Cancel = true;
            };
           
            ETWTrace trace = new ETWTrace();
      
            trace.StartSession(cts.Token);
            
        }
    }

     
}
