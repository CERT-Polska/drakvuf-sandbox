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
        if (DEBUG_VERBOSE)
        {
            PRINT_DEBUG("proc name: %ls\n", pe.szExeFile);
        }
        if (wcscmp(pe.szExeFile, procname) == 0)
        {
            PRINT_DEBUG("found: %ls\n", pe.szExeFile);

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
