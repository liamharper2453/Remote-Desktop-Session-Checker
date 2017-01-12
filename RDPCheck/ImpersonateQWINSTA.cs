using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Net;


namespace impersonateQWINSTA
{
    //Used to launch QWINSTA.exe with parameters as SVCOBIEEADMIN
    //Process.Start() with ProcessStartInfo cannot be used as an alternative to this as a bug is present meaning that any process started with custom credentials will
    //display a CMD window REGARDLESS of the CreateNoWindow parameter being set to true.
    //Bug: https://support.microsoft.com/en-us/kb/818858

    public class ProcessImpersonator
    {
        //Create pipe
        public static void CreatePipe(out SafeFileHandle parentHandle, out SafeFileHandle childHandle, bool parentInputs)
        {
            SECURITY_ATTRIBUTES lpPipeAttributes = new SECURITY_ATTRIBUTES();
            lpPipeAttributes.bInheritHandle = true;
            SafeFileHandle hWritePipe = null;
            try
            {
                if (parentInputs)
                    CreatePipeWithSecurityAttributes(out childHandle, out hWritePipe, lpPipeAttributes, 0);
                else
                    CreatePipeWithSecurityAttributes(out hWritePipe, out childHandle, lpPipeAttributes, 0);
                if (!DuplicateHandle(GetCurrentProcess(), hWritePipe, GetCurrentProcess(), out parentHandle, 0, false, 2))
                    throw new Exception();
            }
            finally
            {
                if ((hWritePipe != null) && !hWritePipe.IsInvalid)
                {
                    hWritePipe.Close();
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
            public SECURITY_ATTRIBUTES()
            {
                nLength = 12;
                lpSecurityDescriptor = IntPtr.Zero;
            }
        }

        //Initialise parameters for kernel32.dll
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe,
            SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, SafeHandle hSourceHandle,
            IntPtr hTargetProcess, out SafeFileHandle targetHandle, int dwDesiredAccess,
            bool bInheritHandle, int dwOptions);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        public static void CreatePipeWithSecurityAttributes(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe,
            SECURITY_ATTRIBUTES lpPipeAttributes, int nSize)
        {
            hReadPipe = null;
            if ((!CreatePipe(out hReadPipe, out hWritePipe, lpPipeAttributes, nSize) || hReadPipe.IsInvalid) || hWritePipe.IsInvalid)
                throw new Exception();
        }


        //Initialise parameters for spawned process
        [Flags]
        enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }

        [Flags]
        enum CreationFlags
        {
            CREATE_SUSPENDED = 0x00000004,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct StartupInfo
        {
            public int cb;
            public string reserved1;
            public string desktop;
            public string title;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public short reserved2;
            public int reserved3;
            public SafeFileHandle hStdInput;
            public SafeFileHandle hStdOutput;
            public short hStdError;

        }
        //Initialise parameters for advapi32.dll
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true,
         SetLastError = true)]
        static extern bool CreateProcessWithLogonW(
            string principal,
            string authority,
            string password,
            LogonFlags logonFlags,
            string appName,
            string cmdLine,
            CreationFlags creationFlags,
            IntPtr environmentBlock,
            string currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInfo processInfo);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);

        // This will use the Logon_NetCredentials_only value.
        // Useful for inter-domain scenario without trust relationship
        // but the system does not validate the credentials.
        public static void ImpersonateProcess_NetCredentials(string appPath, string domain,
            string user, string password, IPAddress ipToCheck)
        {
            ImpersonateProcess(appPath, domain, user, password,
             LogonFlags.LOGON_NETCREDENTIALS_ONLY, ipToCheck);
        }

        // This will use the Logon_With_Profile value.
        // Useful to get the identity of an user in the same domain.
        public static string ImpersonateProcess_WithProfile(string appPath, string domain,
            string user, string password, IPAddress ipToCheck)
        {
            string test = ImpersonateProcess(appPath, domain, user, password, LogonFlags.LOGON_WITH_PROFILE, ipToCheck);

            return test;

        }

        // Call CreateProcessWithLogonW
        private static string ImpersonateProcess(string appPath, string domain, string user,
            string password, LogonFlags lf, IPAddress ipToCheck)
        {
            StartupInfo si = new StartupInfo();
            si.cb = Marshal.SizeOf(typeof(StartupInfo));
            ProcessInfo pi = new ProcessInfo();
            //Flags of STARTF_USESTDHANDLES (used for processing QWINSTA output) and STARTF_USESHOWWINDOW (hides cmd windows)
            si.dwFlags = 0x00000100 + 0x00000001; 
            //Set windows to hidden
            si.wShowWindow = 0;

            SafeFileHandle outputHandle = null;
            SafeFileHandle inputHandle = null;

            //Create pipes for receiving output from QWINSTA.exe
            CreatePipe(out outputHandle, out si.hStdOutput, false);
            CreatePipe(out inputHandle, out si.hStdInput, false);
            //CreatePipe(out errorHandle, out si.hStdError, false);
            StreamWriter standardInput = new StreamWriter(new FileStream(inputHandle, FileAccess.Write, 0x1000, false), Console.InputEncoding, 0x1000);
            standardInput.AutoFlush = true;
            StreamReader reader = new StreamReader(new FileStream(outputHandle, FileAccess.Read, 0x1000, false), Console.OutputEncoding, true, 0x1000);
            string line = "";
            //Launch QWINSTA as SVCOBIEEADMIN
            if (CreateProcessWithLogonW(user, domain, password,
            lf,
            appPath, "/c qwinsta.exe /server:" + Convert.ToString(ipToCheck),
            0, IntPtr.Zero, null,
            ref si, out pi)
            )
            {   
                //rdp-tcp is always last line of QWINSTA (endOfStream does not work here as it hangs)          
                do
                {
                     line = line + reader.ReadLine();
                }
                while (!line.Contains("rdp-tcp"));

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);             

            }
            else
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            return line;
        }
    }
}