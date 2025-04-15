#include "drakvuf_tester_utils.h"
#include <string>
#include <cstdint>
#include <conio.h>
#include <cmath>

static const int NT_CREATE_THREAD_EX_SUSPENDED = 0;
static const int WAIT_TIME = 10000;
static const char SZ_NOTEPAD[] = "C:\\Windows\\SysWOW64\\notepad.exe";
// static const char SZ_NOTEPAD[] = "notepad.exe";
static const WCHAR SZ_CALCAPP[] = L"CalculatorApp.exe";
static const WCHAR SZ_CALC[] = L"calc.exe";
static const char SZ_IEXPLORER[] = "C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe";

enum DrakTestStatus {
    Failed = 0,
    OK = 1
};

using DrakTestStatusFunPtr = DrakTestStatus (*) ();

struct drakTestStruct {
    int id;
    std::string fName;
    DrakTestStatusFunPtr fPtr;
};

/**
 * uses CreateProcessA from hooks.txt (apimon)
 * @param[in] path - application path
 * @param[out] pi - created process info (with handle)
 */
DrakTestStatus CreateProcFromPath(const char* path, PROCESS_INFORMATION* pi, DWORD flags)
{
    char buff[MAX_PATH] = { 0 };
    STARTUPINFOA si;

    strcpy(buff, path);
    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    SecureZeroMemory(pi, sizeof(pi));

    if ( !CreateProcessA(NULL, buff, NULL, NULL, FALSE, flags, NULL, NULL, &si, pi) )
    {
        PRINT_DEBUG("CreateProcessA failed with code: %d\n", GetLastError());
        return DrakTestStatus::Failed;
    }
    WaitForSingleObject(pi->hProcess, WAIT_TIME);

    return DrakTestStatus::OK;
}

DrakTestStatus InjectPayload(HANDLE hProc, unsigned char* payload, size_t payloadSize, LPVOID* remoteProcBuffer, DWORD memProtectFlag)
{
    SIZE_T bytesWritten;

    *remoteProcBuffer = VirtualAllocEx(hProc, NULL, payloadSize, MEM_RESERVE | MEM_COMMIT, memProtectFlag);
    if (*remoteProcBuffer == NULL)
    {
        PRINT_DEBUG("VirtualAllocEx failed with code: %d\n", GetLastError());
        return DrakTestStatus::Failed;
    }

    if (WriteProcessMemory(hProc, *remoteProcBuffer, payload, payloadSize, &bytesWritten) == 0)
    {
        PRINT_DEBUG("WriteProcessMemory failed with code: %d\n", GetLastError());
        return DrakTestStatus::Failed;
    }
    assert(bytesWritten == payloadSize);

    if (DEBUG_VERBOSE)
    {
        ReadRemoteBuffer(hProc, *remoteProcBuffer, payloadSize);
    }

    return DrakTestStatus::OK;
}

DrakTestStatus ExecutePayload(HANDLE hProc, LPVOID remoteProcBuffer, int flags = 0)
{
    HANDLE hThread;
    int res;

    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) remoteProcBuffer, NULL, flags, NULL);
    if (hThread == NULL)
    {
        PRINT_DEBUG("CreateRemoteThread failed with code: %d\n", GetLastError());
        return DrakTestStatus::Failed;
    }
    WaitForSingleObject(hProc, WAIT_TIME);
    CloseHandleErrCheck(hThread);

    return DrakTestStatus::OK;
}

DrakTestStatus FreeVirtMem(HANDLE hProc, LPVOID* remoteProcBuffer, size_t payloadSize)
{
    size_t regionSize = 0;
    HMODULE hNtdll;
    pNtFreeVirtualMemory myNtFreeVirtualMemory;
    int res;
    int status;

    hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL)
    {
        PRINT_DEBUG("GetModuleHandleA (ntdll.dll) failed with code: %d\n", GetLastError());
        return DrakTestStatus::Failed;
    }
    myNtFreeVirtualMemory = (pNtFreeVirtualMemory) GetProcAddress(hNtdll, "NtFreeVirtualMemory");
    if (myNtFreeVirtualMemory == NULL)
    {
        PRINT_DEBUG("GetProcAddress (NtFreeVirtualMemory) failed with code: %d\n", GetLastError());
        return DrakTestStatus::Failed;
    }

    // myNtFreeVirtualMemory(hProc, remoteProcBuffer, &regionSize, MEM_RELEASE);
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntfreevirtualmemory
    // If the MEM_RELEASE flag is set in *FreeType, *RegionSize must be zero.
    status = myNtFreeVirtualMemory(hProc, remoteProcBuffer, &regionSize, MEM_RELEASE);
    if (!NT_SUCCESS(status))
    {
        PRINT_DEBUG("NtFreeVirtualMemory failed with code: %d\n", GetLastError());
        return DrakTestStatus::Failed;
    }

    // todo check if VirtualFreeEx works too:
    // res = VirtualFreeEx(hProc, *remoteProcBuffer, 0, MEM_RELEASE);
    // if (res == 0)
    // {
    //     PRINT_DEBUG("VirtualFreeEx failed with code: %d\n", GetLastError());
    //     return DrakTestStatus::Failed;
    // }
    return DrakTestStatus::OK;
}

DrakTestStatus ChangeMemProtection(HANDLE hProc, LPVOID* remoteProcBuffer, size_t* payloadSize)
{
    HMODULE hNtdll;
    pNtProtectVirtualMemory myNtProtectVirtualMemory;
    ULONG oldAccessProtection;
    NTSTATUS status;

    hNtdll = GetModuleHandleA("ntdll.dll");
    myNtProtectVirtualMemory = (pNtProtectVirtualMemory) GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    status = myNtProtectVirtualMemory(hProc, remoteProcBuffer, (PULONG) payloadSize, PAGE_EXECUTE_READWRITE, &oldAccessProtection);

    if (!NT_SUCCESS(status))
    {
        PRINT_DEBUG("NtProtectVirtualMemory failed with status: %x\n", status);
        return DrakTestStatus::Failed;
    }

    PRINT_DEBUG("old protection: %lu, new protection: %lu\n", oldAccessProtection, PAGE_EXECUTE_READWRITE);

    return DrakTestStatus::OK;
}

DrakTestStatus RemoteInject(HANDLE hProc, unsigned char* payload, size_t* payloadSize, bool runPayload, bool doFree, bool doChangeMemProtection)
{
    LPVOID remoteProcBuffer;
    DWORD memProtectFlag = doChangeMemProtection ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE;

    if (InjectPayload(hProc, payload, *payloadSize, &remoteProcBuffer, memProtectFlag) == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("Injecting payload failed.\n");
        return DrakTestStatus::Failed;
    }

    if (doChangeMemProtection)
    {
        if (ChangeMemProtection(hProc, &remoteProcBuffer, payloadSize) == DrakTestStatus::Failed)
        {
            PRINT_DEBUG("Memory protection change failed.\n");
            return DrakTestStatus::Failed;
        }
    }

    if (runPayload)
    {
        if (ExecutePayload(hProc, remoteProcBuffer) == DrakTestStatus::Failed)
        {
            PRINT_DEBUG("Executing payload failed.\n");
            return DrakTestStatus::Failed;
        }
    }    

    if (doFree)
    {
        if (FreeVirtMem(hProc, &remoteProcBuffer, *payloadSize) == DrakTestStatus::Failed)
        {
            PRINT_DEBUG("Freeing virtual memory failed.\n");
            return DrakTestStatus::Failed;
        }
    }

    // Sleep(3000);
    // int pid;
    // pid = FindProc(L"calc.exe");
    // if (pid != 0)
    // {
    //     HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    //     UINT exitCode = 0;
    //     if (!TerminateProcess(h, exitCode))
    //     {
    //         PRINT_DEBUG("TerminateProcess failed with code: %d\n", GetLastError());
    //     }
    // }
    // pid = FindProc(L"CalculatorApp.exe");
    // if (pid != 0)
    // {
    //     HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    //     UINT exitCode = 0;
    //     if (!TerminateProcess(h, exitCode))
    //     {
    //         PRINT_DEBUG("TerminateProcess failed with code: %d\n", GetLastError());
    //     }
    // }

    return DrakTestStatus::OK;
}

/**
 * TESTS
 */

/*
NtFreeVirtualMemory (regular)
    - needs pseudohandle (-1 == ~0ULL == 0xFFFFFFFF) aquired with GetCurrentProcess()
    - freed memory has to:
        - start with 'MZ' or ...
        - be larger than 0x1000 bytes */
DrakTestStatus NtFreeVirtualMemoryRegularTest()
{
    PRINT_DEBUG("NtFreeVirtualMemoryRegularTest start\n");
    
    HANDLE hProc = GetCurrentProcess();
    size_t payloadSize = sizeof(PAYLOADEK_NO_TERMINATE_LARGE);

    if (RemoteInject(hProc, PAYLOADEK_NO_TERMINATE_LARGE, &payloadSize, true, true, false) == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("Injecting payload failed.\n");
        return DrakTestStatus::Failed;

    }
    CloseHandleErrCheck(hProc);

    PRINT_DEBUG("NtFreeVirtualMemoryRegularTest end\n\n");
    return DrakTestStatus::OK;
;
}

/* 
NtProtectVirtualMemory
    - needs pseudohandle (-1 == ~0ULL == 0xFFFFFFFF) aquired with GetCurrentProcess()
    - affected memory has to start with 'MZ' 
*/
DrakTestStatus NtProtectVirtualMemoryTest()
{
    PRINT_DEBUG("NtProtectVirtualMemoryTest start\n");

    HANDLE hProc = GetCurrentProcess();
    size_t payloadSize = sizeof(PAYLOADEK_NO_TERMINATE_MZ);
    LPVOID remoteProcBuffer;
    DWORD memProtectFlag = PAGE_READWRITE;
    DrakTestStatus status;

    status = InjectPayload(hProc, PAYLOADEK_NO_TERMINATE_MZ, payloadSize, &remoteProcBuffer, memProtectFlag);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("Injecting payload failed.\n");
        goto clean_exit;
    }

    status = ChangeMemProtection(hProc, &remoteProcBuffer, &payloadSize);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("Memory protection change failed.\n");
        goto clean_exit;
    }

    status = ExecutePayload(hProc, ((CHAR*)remoteProcBuffer)+2);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("Executing payload failed.\n");
        goto clean_exit;
    }

    status = FreeVirtMem(hProc, &remoteProcBuffer, payloadSize);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("Freeing virtual memory failed.\n");
        goto clean_exit;
    }

    clean_exit:
    CloseHandleErrCheck(hProc);

    PRINT_DEBUG("NtProtectVirtualMemoryTest end\n\n");
    return status;
}

/* 
NtTerminateProcess
    - needs pseudohandle (-1 == ~0ULL == 0xFFFFFFFF) aquired with GetCurrentProcess()
*/
DrakTestStatus NtTerminateProcessTest()
{
    PRINT_DEBUG("NtTerminateProcessTest start\n");

    PRINT_DEBUG("Not needed, will be executed when the program ends...unless it doesn't.\n");

    PRINT_DEBUG("NtTerminateProcessTest end\n\n");
    return DrakTestStatus::OK;
}

/* 
NtWriteVirtualMemory
    - can't be pseudohandle (-1 == ~0ULL == 0xFFFFFFFF) aquired with GetCurrentProcess()
        - note: comment says: "don't dump self-writes" and checks: "if (process_handle == ~0ULL)",
        so acquiring the handle by OpenProcess(..., GetCurrentProcessId()) would evade this condition (probably unintended?).
*/
DrakTestStatus NtWriteVirtualMemoryTest()
{
    PRINT_DEBUG("NtWriteVirtualMemoryTest start\n");
    
    PROCESS_INFORMATION piNotepad;
    size_t payloadSize = sizeof(PAYLOADEK);
    DrakTestStatus status = DrakTestStatus::OK;
    UINT exitCode = 0;

    status = CreateProcFromPath(SZ_NOTEPAD, &piNotepad, 0);

    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("CreateProcFromPath failed in test %s: \n", __FUNCTION__);
        goto clean_exit;
    }

    status = RemoteInject(piNotepad.hProcess, PAYLOADEK, &payloadSize,  false, true, false);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("RemoteInject failed in test %s: \n", __FUNCTION__);
        goto clean_exit;
    }

    // PostMessage(piNotepad.hProcess, )

    if (!TerminateProcess(piNotepad.hProcess, exitCode))
    {
        PRINT_DEBUG("TerminateProcess failed with code: %d\n", GetLastError());
    }
    clean_exit:
    CloseHandleErrCheck(piNotepad.hProcess);
    CloseHandleErrCheck(piNotepad.hThread);

    PRINT_DEBUG("NtWriteVirtualMemoryTest end\n\n");
    return status;
}

/* 
NtCreateThreadEx
    - needs to be called from CreateRemoteThread (if (target_process_pid == info->proc_data.pid) -> exit)
*/
DrakTestStatus NtCreateThreadExTest()
{
    PRINT_DEBUG("NtCreateThreadExTest start\n");

    DWORD pid;
    PROCESS_INFORMATION piNotepad;
    size_t payloadSize = sizeof(PAYLOADEK);
    DrakTestStatus status;
    UINT exitCode = 0;

    status = CreateProcFromPath(SZ_NOTEPAD, &piNotepad, 0);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("CreateProcFromPath failed in test %s: \n", __FUNCTION__);
        goto clean_exit;
    }

    status = RemoteInject(piNotepad.hProcess, PAYLOADEK, &payloadSize, true, false, false);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("RemoteInject failed in test %s: \n", __FUNCTION__);
    }

    // if (!TerminateProcess(piNotepad.hProcess, exitCode))
    // {
    //     PRINT_DEBUG("TerminateProcess failed with code: %d\n", GetLastError());
    // }
    clean_exit:
    CloseHandleErrCheck(piNotepad.hProcess);
    CloseHandleErrCheck(piNotepad.hThread);

    PRINT_DEBUG("NtCreateThreadExTest end\n\n");
    return status;
}

// TODO try NtSetContextThread and SetThreadContext
/* 
NtSetInformationThread
    - needs to be called with "ThreadWow64Context" as a second argument: "IN THREADINFOCLASS ThreadInformationClass,"
    - needs to be called on a remote process
*/
DrakTestStatus NtSetInformationThreadTest()
{
    PRINT_DEBUG("NtSetInformationThreadTest start\n");

    PROCESS_INFORMATION pi;
    HMODULE hNtdll;
    pNtSetInformationThread myNtSetInformationThread;
    pNtQueryInformationThread myNtQueryInformationThread;
    NTSTATUS ntStatus;
    WOW64_CONTEXT wow64Context;
    wow64Context.ContextFlags = WOW64_CONTEXT_ALL;
    DWORD status;
    BOOL isWow64;
    DrakTestStatus drakStatus;
    UINT exitCode = 0;
    const char* procName = SZ_NOTEPAD;

    drakStatus = CreateProcFromPath(procName, &pi, CREATE_SUSPENDED);
    if (drakStatus == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("CreateProcFromPath failed in test %s: \n", __FUNCTION__);
        goto clean_exit;
    }

    if (!IsWow64Process(pi.hProcess, &isWow64))
    {
        PRINT_DEBUG("IsWow64Process failed with err: %d\n", GetLastError());
        drakStatus = DrakTestStatus::Failed;
        goto clean_exit;
    }

    if (!isWow64)
    {
        PRINT_DEBUG("Process %s not Wow64Process. Exiting.\n", procName);
        drakStatus = DrakTestStatus::Failed;
        goto clean_exit;
    }

    // status = Wow64SuspendThread(pi.hThread);
    // if (status < 0)
    // {
    //     PRINT_DEBUG("Wow64SuspendThread failed with status: %d\n", status);
    //     drakStatus = DrakTestStatus::Failed;
    //     goto clean_exit;
    // }

    if (!Wow64GetThreadContext(pi.hThread, &wow64Context))
    {
        PRINT_DEBUG("Wow64GetThreadContext failed with err: %d\n", GetLastError());
        drakStatus = DrakTestStatus::Failed;
        goto clean_exit;
    }

    hNtdll = GetModuleHandleA("ntdll.dll");
    myNtSetInformationThread = (pNtSetInformationThread) GetProcAddress(hNtdll, "NtSetInformationThread");
    myNtQueryInformationThread = (pNtQueryInformationThread) GetProcAddress(hNtdll, "NtQueryInformationThread");

    ntStatus = myNtQueryInformationThread(pi.hThread, (THREADINFOCLASS) ThreadWow64Context, &wow64Context, sizeof(wow64Context), NULL);

    if (!NT_SUCCESS(ntStatus))
    {
        PRINT_DEBUG("NtQueryInformationThread failed with status: %x\n", ntStatus);
        drakStatus = DrakTestStatus::Failed;
        goto clean_exit;
    }

    // ReadPageProtections(pi.hProcess, wow64Context.Eax);
    // ReadPageProtections(pi.hProcess, wow64Context.Eip);
    
    ntStatus = myNtSetInformationThread(pi.hThread, (THREADINFOCLASS) ThreadWow64Context, &wow64Context, sizeof(wow64Context));

    if (!NT_SUCCESS(ntStatus))
    {
        PRINT_DEBUG("NtSetInformationThread failed with status: %x\n", ntStatus);
        drakStatus = DrakTestStatus::Failed;
        goto clean_exit;
    }
    status = ResumeThread(pi.hThread);
    if (!NT_SUCCESS(ntStatus))
    {
        PRINT_DEBUG("ResumeThread failed with status: %x\n", ntStatus);
        drakStatus = DrakTestStatus::Failed;
        goto clean_exit;
    }
    WaitForSingleObject(pi.hThread, WAIT_TIME);

    if (!TerminateProcess(pi.hProcess, exitCode))
    {
        PRINT_DEBUG("TerminateProcess failed with code: %d\n", GetLastError());
    }
    clean_exit:
    CloseHandleErrCheck(pi.hThread);
    CloseHandleErrCheck(pi.hProcess);

    PRINT_DEBUG("NtSetInformationThreadTest end\n\n");
    return drakStatus;
}

/* 
NtFreeVirtualMemory (shellcode)
    - no particular requirements
*/
DrakTestStatus NtFreeVirtualMemoryShellcodeTest()
{
    PRINT_DEBUG("NtFreeVirtualMemoryShellcodeTest start\n");
 
    PROCESS_INFORMATION piNotepad;
    size_t payloadSize = sizeof(PAYLOADEK);
    DrakTestStatus status;
    UINT exitCode = 0;

    status = CreateProcFromPath(SZ_NOTEPAD, &piNotepad, 0);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("CreateProcFromPath failed in test %s: \n", __FUNCTION__);
        goto clean_exit;
    }

    status = RemoteInject(piNotepad.hProcess, PAYLOADEK, &payloadSize, false, true, false);
    if (status == DrakTestStatus::Failed)
    {
        PRINT_DEBUG("RemoteInject failed in test %s: \n", __FUNCTION__);
    }

    clean_exit:
    if (!TerminateProcess(piNotepad.hProcess, exitCode))
    {
        PRINT_DEBUG("TerminateProcess failed with code: %d\n", GetLastError());
    }
    CloseHandleErrCheck(piNotepad.hProcess);
    CloseHandleErrCheck(piNotepad.hThread);

    PRINT_DEBUG("NtFreeVirtualMemoryShellcodeTest end\n\n");
    return status;
}

int main(int argc, char* argv[])
{
    bool waitOnExit = false;
    int mask = (1 << 0) * 1
             + (1 << 1) * 1
             + (1 << 2) * 1
             + (1 << 3) * 1
             + (1 << 4) * 1
             + (1 << 5) * 1
             + (1 << 6) * 1
             ;
    drakTestStruct drakTests[] = {
        { 0, "NtFreeVirtualMemoryShellcodeTest", NtFreeVirtualMemoryShellcodeTest },
        { 1, "NtFreeVirtualMemoryRegularTest", NtFreeVirtualMemoryRegularTest },
        { 2, "NtProtectVirtualMemoryTest", NtProtectVirtualMemoryTest },
        { 3, "NtTerminateProcessTest", NtTerminateProcessTest },
        { 4, "NtWriteVirtualMemoryTest", NtWriteVirtualMemoryTest },
        { 5, "NtCreateThreadExTest", NtCreateThreadExTest },
        { 6, "NtSetInformationThreadTest", NtSetInformationThreadTest },
    };
    size_t dtLen = sizeof(drakTests) / sizeof(drakTests[0]);
    int testsOk = 0;
    int testsRun = 0;

    for (size_t i = 0; i < dtLen; i++)
    {
        DrakTestStatus status;
        if (mask & (1 << i))
        {
            testsRun++;
            printf("running test %d: %s\n", drakTests[i].id, drakTests[i].fName.c_str());
            status = drakTests[i].fPtr();
            testsOk += status;
            // if (status == DrakTestStatus::OK)
            // {
            //     testsOk++;
            // }
        }
    }
    PRINT_DEBUG("Tests done, %d / %d OK.\n", testsOk, testsRun);
    if (waitOnExit)
    {
        PRINT_DEBUG("Press any key to exit.\n");
        getch();
    }
    else
    {
        Sleep(WAIT_TIME);
    }

    return 0;
}
