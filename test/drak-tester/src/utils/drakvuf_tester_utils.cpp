#include "drakvuf_tester_utils.h"

void CloseHandleErrCheck(HANDLE handle)
{
    if (!CloseHandle(handle))
    {
        PRINT_DEBUG("CloseHandle failed with code: %d\n", GetLastError());
    }
}

void PrintBytesFromMem(LPVOID buffer, SIZE_T bufferSize)
// void PrintBytesFromMem(LPVOID buffer, SIZE_T bufferSize, const unsigned char* payload)
{
    printf("bytes int: %x\n", ((int*)buffer)[0]);
    for (size_t i = 0; i < bufferSize; i++)
    {
        printf("%hhx ", ((BYTE*)buffer)[i]);
        // assert(((BYTE*)buffer)[i] == payload[i]);
    }
    printf("\n");
}

DWORD FindProc(const WCHAR* procname)
{
    HANDLE hProcSnapshot;
    PROCESSENTRY32W pe;
    BOOL result;

    hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    pe.dwSize = sizeof(PROCESSENTRY32W);
    result = Process32FirstW(hProcSnapshot, &pe);

    while (result)
    {
        PRINT_DEBUG_VERBOSE("proc name: %ls\n", pe.szExeFile);
        if (wcscmp(pe.szExeFile, procname) == 0)
        {
            // PRINT_DEBUG("found: %ls\n", pe.szExeFile);
            return pe.th32ProcessID;
        }
        result = Process32NextW(hProcSnapshot, &pe);
    }

    return 0;
}

void CheckProcStatus(HANDLE hProc)
{
    DWORD lpExitCode;

    GetExitCodeProcess(hProc, &lpExitCode);
    printf("notepad status: %d\n", lpExitCode);
}

void ReadRemoteBuffer(HANDLE hProc, LPVOID remoteProcBuffer, size_t buffSize)
{
    void* localRemoteProcBuffer = malloc(buffSize);
    SIZE_T bytesRead;

    ReadProcessMemory(hProc, remoteProcBuffer, localRemoteProcBuffer, buffSize, &bytesRead);
    PRINT_DEBUG("ReadProcessMemory bytes read: %zu\n", bytesRead);
    PrintBytesFromMem(localRemoteProcBuffer, bytesRead);

    free(localRemoteProcBuffer);
}

void PrintProtectionFlags(DWORD protection) {
    printf("Protection: ");
    if (protection & PAGE_EXECUTE_READWRITE)
    {
        printf("EXECUTE_READWRITE ");
    }
    if (protection & PAGE_EXECUTE_READ)
    {
        printf("EXECUTE_READ ");
    }
    if (protection & PAGE_READWRITE)
    {
        printf("READWRITE ");
    }
    if (protection & PAGE_READONLY)
    {
        printf("READONLY ");
    }
    if (protection & PAGE_WRITECOPY)
    {
        printf("WRITECOPY ");
    }
    if (protection & PAGE_EXECUTE_WRITECOPY)
    {
        printf("EXECUTE_WRITECOPY ");
    }
    if (protection & PAGE_NOACCESS)
    {
        printf("NOACCESS ");
    }
    if (protection & PAGE_GUARD)
    {
        printf("GUARD ");
    }
    printf("\n");
}

void ReadPageProtections(HANDLE hProcess, DWORD targetAddress) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = 0;

    printf("reading page protection for address: %x\n", targetAddress);
    // while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
    // {
    //     if (mbi.State == MEM_COMMIT)
    //     {
    //         printf("Base: %p | Size: %zu | ", mbi.BaseAddress, mbi.RegionSize);
    //         PrintProtectionFlags(mbi.Protect);
    //     }
        
    //     addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    // }
    SIZE_T result = VirtualQueryEx(hProcess, (LPCVOID) (DWORD_PTR) targetAddress, &mbi, sizeof(mbi));

    if (result == 0)
    {
        printf("VirtualQueryEx failed: %lu\n", GetLastError());
        return;
    }

    if (mbi.State != MEM_COMMIT)
    {
        printf("Address not in committed memory\n");
        return;
    }

    PrintProtectionFlags(mbi.Protect);
    return;
}
