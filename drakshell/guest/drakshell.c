// gcc  headless.c
// objcopy -O binary --only-section=.text a.out out_objcopy_onlysection
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nt_loader.h"

#define REQ_PING 0x30
#define REQ_INTERACTIVE_EXECUTE 0x31
#define REQ_EXECUTE_AND_FINISH 0x32
#define REQ_FINISH 0x33
#define REQ_BLOCK 0x34

#define RESP_PONG 0x30
#define RESP_INTERACTIVE_EXECUTE_START 0x31
#define RESP_EXECUTE_AND_FINISH_START 0x32
#define RESP_FINISH_START 0x33
#define RESP_BLOCK 0x34

#define RESP_BAD_REQ 0x40
#define RESP_FATAL_FINISH 0x41

static bool recvn(HANDLE hComm, LPBYTE buffer, DWORD size) {
    DWORD bytesRead = 0;

    while(size > 0) {
        if(!ReadFile(hComm, buffer, size, &bytesRead, NULL)) {
            return false;
        }
        if(!bytesRead) {
            return false;
        }
        size -= bytesRead;
        buffer += bytesRead;
    }
    return true;
}

static bool sendn(HANDLE hComm, LPBYTE buffer, DWORD size) {
    DWORD bytesWritten = 0;

    while(size > 0) {
        if(!WriteFile(hComm, buffer, size, &bytesWritten, NULL)) {
            return false;
        }
        if(!bytesWritten) {
            return false;
        }
        size -= bytesWritten;
        buffer += bytesWritten;
    }
    return true;
}

static bool recv_control(HANDLE hComm, LPBYTE req) {
    return recvn(hComm, req, sizeof(*req));
}

static bool send_control(HANDLE hComm, BYTE resp) {
    return sendn(hComm, &resp, sizeof(resp));
}

static bool recv_block(HANDLE hComm, LPBYTE bufferToRecv, LPWORD argSize, WORD argMaxSize) {
    if(!recvn(hComm, (LPBYTE)argSize, sizeof(*argSize))) {
        return false;
    }
    if(*argSize > argMaxSize) {
        return false;
    }
    return recvn(hComm, bufferToRecv, *argSize);
}

static bool send_block(HANDLE hComm, LPBYTE bufferToSend, WORD argSize) {
    if(!sendn(hComm, (LPBYTE)&argSize, sizeof(argSize))) {
        return false;
    }
    if(!argSize)
        return true;
    return sendn(hComm, bufferToSend, argSize);
}

typedef struct _STD_HANDLES {
    HANDLE hStdinRead;
    HANDLE hStdinWrite;
    HANDLE hStdoutRead;
    HANDLE hStdoutWrite;
    HANDLE hStderrRead;
    HANDLE hStderrWrite;
} STD_HANDLES, *PSTD_HANDLES;

static bool init_std_handles(PSTD_HANDLES handles) {
    SECURITY_ATTRIBUTES saInheritHandle;

    saInheritHandle.nLength = sizeof(SECURITY_ATTRIBUTES);
    saInheritHandle.bInheritHandle = true;
    saInheritHandle.lpSecurityDescriptor = NULL;

    handles->hStdinRead = INVALID_HANDLE_VALUE;
    handles->hStdinWrite = INVALID_HANDLE_VALUE;
    handles->hStdoutRead = INVALID_HANDLE_VALUE;
    handles->hStdoutWrite = INVALID_HANDLE_VALUE;
    handles->hStderrRead = INVALID_HANDLE_VALUE;
    handles->hStderrWrite = INVALID_HANDLE_VALUE;

    if(!CreatePipe(&(handles->hStdinRead), &(handles->hStdinWrite), &saInheritHandle, 0)) {
        return false;
    }
    if(!SetHandleInformation(handles->hStdinWrite, HANDLE_FLAG_INHERIT, 0)) {
        return false;
    }
    if(!CreatePipe(&(handles->hStdoutRead), &(handles->hStdoutWrite), &saInheritHandle, 0)) {
        return false;
    }
    if(!SetHandleInformation(handles->hStdoutWrite, HANDLE_FLAG_INHERIT, 0)) {
        return false;
    }
    if(!CreatePipe(&(handles->hStderrRead), &(handles->hStderrWrite), &saInheritHandle, 0)) {
        return false;
    }
    if(!SetHandleInformation(handles->hStderrWrite, HANDLE_FLAG_INHERIT, 0)) {
        return false;
    }
    return true;
}

static void close_std_handles(PSTD_HANDLES handles) {
    if(handles->hStdinRead != INVALID_HANDLE_VALUE) {
        CloseHandle(handles->hStdinRead);
        handles->hStdinRead = INVALID_HANDLE_VALUE;
    }
    if(handles->hStdoutRead != INVALID_HANDLE_VALUE) {
        CloseHandle(handles->hStdoutRead);
        handles->hStdoutRead = INVALID_HANDLE_VALUE;
    }
    if(handles->hStderrRead != INVALID_HANDLE_VALUE) {
        CloseHandle(handles->hStderrRead);
        handles->hStderrRead = INVALID_HANDLE_VALUE;
    }
    if(handles->hStdinWrite != INVALID_HANDLE_VALUE) {
        CloseHandle(handles->hStdinWrite);
        handles->hStdinWrite = INVALID_HANDLE_VALUE;
    }
    if(handles->hStdoutWrite != INVALID_HANDLE_VALUE) {
        CloseHandle(handles->hStdoutWrite);
        handles->hStdoutWrite = INVALID_HANDLE_VALUE;
    }
    if(handles->hStderrWrite != INVALID_HANDLE_VALUE) {
        CloseHandle(handles->hStderrWrite);
        handles->hStderrWrite = INVALID_HANDLE_VALUE;
    }
}

static bool create_interactive_process(LPWSTR szCmdline, PSTD_HANDLES std_handles, PHANDLE lphProcess) {
    BOOL bSuccess;
    PROCESS_INFORMATION piProcInfo = {0};
    STARTUPINFOW siStartInfo = {0};

    siStartInfo.cb = sizeof(STARTUPINFOW);
    siStartInfo.hStdError = std_handles->hStderrWrite;
    siStartInfo.hStdOutput = std_handles->hStdoutWrite;
    siStartInfo.hStdInput = std_handles->hStdinRead;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    bSuccess = CreateProcessW(NULL,
        szCmdline,     // command line
        NULL,          // process security attributes
        NULL,          // primary thread security attributes
        true,          // handles are inherited
        0,             // creation flags
        NULL,          // use parent's environment
        NULL,          // use parent's current directory
        &siStartInfo,  // STARTUPINFO pointer
        &piProcInfo    // receives PROCESS_INFORMATION
    );
    if(!bSuccess) {
        return false;
    } else {
        // Close handle to the main thread
        CloseHandle(piProcInfo.hThread);
        // Close handles to the child-side of pipes
        // because inheritance made a duplicates
        CloseHandle(std_handles->hStderrWrite);
        std_handles->hStderrWrite = INVALID_HANDLE_VALUE;
        CloseHandle(std_handles->hStdoutWrite);
        std_handles->hStdoutWrite = INVALID_HANDLE_VALUE;
        CloseHandle(std_handles->hStdinRead);
        std_handles->hStdinRead = INVALID_HANDLE_VALUE;
        // Pass process handle to the caller
        *lphProcess = piProcInfo.hProcess;
        return true;
    }
}

static bool interactive_execute(HANDLE hComm) {
     union {
        struct {
            wchar_t commandLine[1024];
        };
        struct {
            BYTE stdinBuffer[1024];
            BYTE stdoutBuffer[1024];
            BYTE stderrBuffer[1024];
        };
    } buffers;
    WORD readBytes = 0;
    BYTE control = 0;
    STD_HANDLES std_handles = {0};
    HANDLE hProcess;

    // Receive command line
    if(!recv_control(hComm, &control)) {
        return false;
    }
    if(control != REQ_BLOCK) {
        // We probably lost sync in the middle
        // and there is another try to use drakshell.
        // Let's finish this mode gracefully
        if(!send_control(hComm, RESP_BAD_REQ)) {
            return false;
        }
        return true;
    }
    if(!recv_block(hComm, (LPBYTE)buffers.commandLine, &readBytes, sizeof(buffers.commandLine) - sizeof(wchar_t))) {
        return false;
    }
    // Ensure terminator at the end
    buffers.commandLine[readBytes] = 0;
    if(!init_std_handles(&std_handles)) {
        close_std_handles(&std_handles);
        return false;
    }

    if(!create_interactive_process(buffers.commandLine, &std_handles, &hProcess)) {
        // TODO: Send GLE status code
        close_std_handles(&std_handles);
        return true; // Not a fatal error
    }

    // Message loop
    OVERLAPPED opStdin = {0};
    OVERLAPPED opStdout = {0};
    OVERLAPPED opStderr = {0};
    BOOL stdinPending = false;
    BOOL stdoutPending = false;
    BOOL stderrPending = false;

    opStdin.hEvent = CreateEvent(NULL, true, true, NULL);
    opStdout.hEvent = CreateEvent(NULL, true, true, NULL);
    opStderr.hEvent = CreateEvent(NULL, true, true, NULL);

    while(true) {
        HANDLE waitable_handles[4] = {
            opStdin.hEvent, opStdout.hEvent, opStderr.hEvent, hProcess
        };
        DWORD status = WaitForMultipleObjects(
            4, waitable_handles, false, 0xFFFFFFFF
        );
        if(status == 0) {
            // stdin packet from drakshell client
            if(stdinPending) {
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stdin to the process
            }
        }
        else if (status == 1) {
            // stdout packet from process
            if(stdoutPending) {
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stdout to the client
            }
        }
        else if (status == 2) {
            // stderr packet from process
            if(stderrPending) {
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stderr to the client
            }
        }
        else if (status == 3) {
            // process is terminated
            // Close everything and report the exit code
        }
        else {
            // something went wrong
            // Terminate process, close everything and report the fatal error
        }
    }
}

static bool execute_and_finish() {

}

void __attribute__((noinline)) __attribute__((force_align_arg_pointer)) drakshell_main() {
    DCB dcb = { .DCBlength = sizeof(DCB) };

    if(!load_winapi()) {
        // Failed to load some WinAPI functions
        return;
    }

    Sleep(500); // Some sleep to let injector finish his job

    OutputDebugStringW(L"Hello from drakshell");

    HANDLE hComm = CreateFileW(
        L"\\\\.\\COM1",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if(hComm == INVALID_HANDLE_VALUE)
    {
        OutputDebugStringW(L"Failed to connect to COM1");
        return;
    }

    if(!GetCommState(hComm, &dcb))
    {
        OutputDebugStringW(L"Failed to get mode of COM1");
        return;
    }

    dcb.BaudRate = 115200;
    dcb.fParity = true;

    if(!SetCommState(hComm, &dcb))
    {
        OutputDebugStringW(L"Failed to set mode of COM1");
        return;
    }

    OutputDebugStringW(L"I'm connected");

    while(true) {
        BYTE control = 0;
        if(!recv_control(hComm, &control)) {
            OutputDebugStringW(L"Failed to receive request control byte");
            break;
        }
        if(control == REQ_PING) {
            // Ping checks if shell is in initial state
            // and is able to receive commands
            if(!send_control(hComm, RESP_PONG)) {
                OutputDebugStringW(L"Failed to send RESP_PONG response");
                break;
            }
        }
        else if(control == REQ_INTERACTIVE_EXECUTE) {
            if(!send_control(hComm, RESP_INTERACTIVE_EXECUTE_START)) {
                OutputDebugStringW(L"Failed to send RESP_INTERACTIVE_EXECUTE_START response");
                break;
            }
            if(!interactive_execute(hComm)) {
                OutputDebugStringW(L"Fatal error in interactive execute mode");
                break;
            }
        }
        else if(control == REQ_EXECUTE_AND_FINISH) {
            if(!send_control(hComm, RESP_EXECUTE_AND_FINISH_START)) {
                OutputDebugStringW(L"Failed to send RESP_INTERACTIVE_EXECUTE_START response");
                break;
            }
            if(!execute_and_finish()) {
                OutputDebugStringW(L"Fatal error in interactive execute mode");
            }
            // We're always finishing here
            break;
        }
        else if(control == REQ_FINISH) {
            if(!send_control(hComm, RESP_FINISH_START)) {
                OutputDebugStringW(L"Failed to send RESP_FINISH_START response");
            }
            break;
        } else {
            if(!send_control(hComm, RESP_BAD_REQ)) {
                OutputDebugStringW(L"Failed to send RESP_BAD_REQ response");
                break;
            }
        }
    }
    OutputDebugStringW(L"Bye");
    CloseHandle(hComm);
}

extern void thread_start();

// Tell the compiler incoming stack alignment is not RSP%16==8 or ESP%16==12
__attribute__((force_align_arg_pointer))
__attribute__((section(".startup")))
void _start() {
    // Escape from hijacked thread to the dedicated thread ASAP
    // This will cause injector to recover the original thread
    // and make possible to do any long-term actions without interfering
    // with explorer.exe operations

    // Universal get_pc_thunk for further cleanup
    // _start will be for sure somewhere on the first page
    // of injected code allocation
    volatile void* base_ptr;
    asm("call _next\n\t"
        "_next: pop %0": "=r"(base_ptr));

    PCreateThread pCreateThread = get_func_from_peb(L"kernel32.dll", "CreateThread");
    (*pCreateThread)(
        NULL, // lpThreadAttributes
        0,    // dwStackSize
        thread_start,
        (void*)base_ptr, // lpParameter
        0,    // dwCreationFlags
        NULL // lpThreadId
    );
}