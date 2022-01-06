using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace MemoryLib.Core;

public class Memory
{
    [Flags]
    public enum ProcessAccessType
    {
        PROCESS_TERMINATE = 1,
        PROCESS_CREATE_THREAD = 2,
        PROCESS_SET_SESSIONID = 4,
        PROCESS_VM_OPERATION = 8,
        PROCESS_VM_READ = 16,
        PROCESS_VM_WRITE = 32,
        PROCESS_DUP_HANDLE = 64,
        PROCESS_CREATE_PROCESS = 128,
        PROCESS_SET_QUOTA = 256,
        PROCESS_SET_INFORMATION = 512,
        PROCESS_QUERY_INFORMATION = 1024
    }

    private IntPtr m_hProcess = IntPtr.Zero;

    public Process ReadProcess { get; set; } = null;

    public void Open()
    {
        m_hProcess = OpenProcess(0x1F0FFF, 1, (uint) ReadProcess.Id);
    }

    public void CloseHandle()
    {
        if (CloseHandle(m_hProcess) == 0)
            throw new Exception("CloseHandle Failed");
    }

    public byte[] Read(IntPtr MemoryAddress, uint bytesToRead, out int bytesRead)
    {
        var buffer = new byte[(long) (IntPtr) bytesToRead];
        ReadProcessMemory(m_hProcess, MemoryAddress, buffer, bytesToRead, out var lpNumberOfBytesRead);
        bytesRead = lpNumberOfBytesRead.ToInt32();
        return buffer;
    }

    public byte[] PointerRead(IntPtr MemoryAddress, uint bytesToRead, int[] Offset, out int bytesRead)
    {
        var num1 = Offset.Length;
        bytesRead = 0;
        var buffer1 = new byte[4];
        var num2 = 0;
        if (num1 == 0)
        {
            ReadProcessMemory(m_hProcess, MemoryAddress, buffer1, 4U, out _);
            var num3 = ToDec(Make(buffer1)) + Offset[1];
            var buffer2 = new byte[(long) (IntPtr) bytesToRead];
            ReadProcessMemory(m_hProcess, (IntPtr) num3, buffer2, bytesToRead, out var lpNumberOfBytesRead);
            bytesRead = lpNumberOfBytesRead.ToInt32();
            return buffer2;
        }

        for (var index = 0; index <= num1; ++index)
        {
            if (index == num1)
            {
                ReadProcessMemory(m_hProcess, (IntPtr) num2, buffer1, 4U, out var lpNumberOfBytesRead);
                bytesRead = lpNumberOfBytesRead.ToInt32();
                return buffer1;
            }

            if (index == 0)
            {
                ReadProcessMemory(m_hProcess, MemoryAddress, buffer1, 4U, out _);
                num2 = ToDec(Make(buffer1)) + Offset[index];
            }
            else
            {
                ReadProcessMemory(m_hProcess, (IntPtr) num2, buffer1, 4U, out _);
                num2 = ToDec(Make(buffer1)) + Offset[index];
            }
        }

        return buffer1;
    }

    public void Write(IntPtr MemoryAddress, byte[] bytesToWrite, out int bytesWritten)
    {
        WriteProcessMemory(m_hProcess, MemoryAddress, bytesToWrite, (uint) bytesToWrite.Length,
            out var lpNumberOfBytesWritten);
        bytesWritten = lpNumberOfBytesWritten.ToInt32();
    }

    public string PointerWrite(IntPtr MemoryAddress, byte[] bytesToWrite, int[] Offset, out int bytesWritten)
    {
        var num1 = Offset.Length;
        bytesWritten = 0;
        var buffer = new byte[4];
        var Decimal1 = 0;
        if (num1 == 0)
        {
            ReadProcessMemory(m_hProcess, MemoryAddress, buffer, 4U, out _);
            var Decimal2 = ToDec(Make(buffer)) + Offset[1];
            WriteProcessMemory(m_hProcess, (IntPtr) Decimal2, bytesToWrite, (uint) bytesToWrite.Length,
                out var num2);
            bytesWritten = num2.ToInt32();
            return ToHex(Decimal2);
        }

        for (var index = 0; index <= num1; ++index)
        {
            if (index == num1)
            {
                WriteProcessMemory(m_hProcess, (IntPtr) Decimal1, bytesToWrite, (uint) bytesToWrite.Length,
                    out var num2);
                bytesWritten = num2.ToInt32();
                return ToHex(Decimal1);
            }

            if (index == 0)
            {
                ReadProcessMemory(m_hProcess, MemoryAddress, buffer, 4U, out _);
                Decimal1 = ToDec(Make(buffer)) + Offset[index];
            }
            else
            {
                ReadProcessMemory(m_hProcess, (IntPtr) Decimal1, buffer, 4U, out _);
                Decimal1 = ToDec(Make(buffer)) + Offset[index];
            }
        }

        return ToHex(Decimal1);
    }

    public int PID()
    {
        return ReadProcess.Id;
    }

    public string BaseAddressH()
    {
        return ToHex(ReadProcess.MainModule.BaseAddress.ToInt32());
    }

    public int BaseAddressD()
    {
        return ReadProcess.MainModule.BaseAddress.ToInt32();
    }

    public static string Make(byte[] buffer)
    {
        var str = "";
        for (var index = 0; index < buffer.Length; ++index)
            str = buffer[index].ToString("X2") + str;
        return str;
    }

    public void Alloc(out int Addr, int Size)
    {
        Addr = MemoryAPI.VirtualAllocEx(m_hProcess, IntPtr.Zero, Size, MemoryAPI.AllocType.Commit,
            MemoryAPI.Protect.ExecuteReadWrite);
    }

    public bool Dealloc(int Addr)
    {
        return MemoryAPI.VirtualFreeEx(m_hProcess, (IntPtr) Addr, 0, MemoryAPI.FreeType.Release);
    }

    public static string ToHex(int Decimal)
    {
        return Decimal.ToString("X");
    }

    public static int ToDec(string Hex)
    {
        return int.Parse(Hex, NumberStyles.HexNumber);
    }

    public static float ToFloat(string Hex)
    {
        return BitConverter.ToSingle(BitConverter.GetBytes(uint.Parse(Hex, NumberStyles.AllowHexSpecifier)), 0);
    }

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern int CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In] [Out] byte[] buffer,
        uint size, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In] [Out] byte[] buffer,
        uint size, out IntPtr lpNumberOfBytesWritten);
}

internal class MemoryAPI
{
    [Flags]
    public enum AllocType
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000
    }

    [Flags]
    public enum FreeType
    {
        Decommit = 0x4000,
        Release = 0x8000
    }

    [Flags]
    public enum Protect
    {
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40
    }


    [DllImport("kernel32.dll")]
    public static extern int VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize,
        AllocType flAllocationType, Protect flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, FreeType dwFreeType);
}