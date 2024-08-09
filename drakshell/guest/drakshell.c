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
#define RESP_STDOUT_BLOCK 0x34
#define RESP_STDERR_BLOCK 0x35
#define RESP_INTERACTIVE_EXECUTE_PROCESS_CREATED 0x36
#define RESP_INTERACTIVE_EXECUTE_END 0x37

#define RESP_BAD_REQ 0x40
#define RESP_FATAL_ERROR 0x41

static bool recvn(HANDLE hComm, LPBYTE buffer, DWORD size) {
    DWORD bytesRead = 0;

    while(size > 0) {
        if(!ReadFile(hComm, buffer, size, &bytesRead, NULL)) {
            OutputDebugStringW(L"recvn: ReadFile failed");
            return false;
        }
        if(!bytesRead) {
            OutputDebugStringW(L"recvn: Broken pipe");
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
            OutputDebugStringW(L"sendn: WriteFile failed");
            return false;
        }
        if(!bytesWritten) {
            OutputDebugStringW(L"sendn: Broken pipe");
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
        OutputDebugStringW(L"recv_block: Buffer overflow");
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

static bool send_control_with_code(HANDLE hComm, BYTE resp, DWORD code) {
    if(!send_control(hComm, resp)) {
        return false;
    }
    return sendn(hComm, (LPBYTE)&code, sizeof(code));
}

static bool send_fatal_error(HANDLE hComm, DWORD gle) {
    return send_control_with_code(hComm, RESP_FATAL_ERROR, gle);
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

    handles->hStdinRead = CreateNamedPipe(
        L"\\\\.\\pipe\\drakshell-stdin",
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        0, // byte & wait mode
        1,
        4096,
        4096,
        0,
        &saInheritHandle
    );

    if(handles->hStdinRead == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(L"init_std_handles: CreateNamedPipe failed for stdin");
        return false;
    }

    handles->hStdinWrite = CreateFileW(
        L"\\\\.\\pipe\\drakshell-stdin",
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if(handles->hStdinWrite == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(L"init_std_handles: CreateFileW failed for stdin");
        return false;
    }

    handles->hStdoutWrite = CreateNamedPipe(
        L"\\\\.\\pipe\\drakshell-stdout",
        PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
        0, // byte & wait mode
        1,
        4096,
        4096,
        0,
        &saInheritHandle
    );

    if(handles->hStdoutWrite == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(L"init_std_handles: CreateNamedPipe failed for stdout");
        return false;
    }

    handles->hStdoutRead = CreateFileW(
        L"\\\\.\\pipe\\drakshell-stdout",
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if(handles->hStdoutRead == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(L"init_std_handles: CreateFileW failed for stdout");
        return false;
    }

    handles->hStderrWrite = CreateNamedPipe(
        L"\\\\.\\pipe\\drakshell-stderr",
        PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
        0, // byte & wait mode
        1,
        4096,
        4096,
        0,
        &saInheritHandle
    );

    if(handles->hStderrWrite == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(L"init_std_handles: CreateNamedPipe failed for stderr");
        return false;
    }

    handles->hStderrRead = CreateFileW(
        L"\\\\.\\pipe\\drakshell-stderr",
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if(handles->hStderrRead == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(L"init_std_handles: CreateFileW failed for stderr");
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
    siStartInfo.dwFlags = STARTF_USESTDHANDLES;

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
    WORD commandLineBytesRead = 0;
    BYTE control = 0;
    STD_HANDLES std_handles = {0};
    HANDLE hProcess;

    // Receive command line
    if(!recv_control(hComm, &control)) {
        send_control(hComm, RESP_BAD_REQ);
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
    if(!recv_block(hComm, (LPBYTE)buffers.commandLine, &commandLineBytesRead, sizeof(buffers.commandLine) - sizeof(wchar_t))) {
        send_control(hComm, RESP_BAD_REQ);
        return false;
    }
    // Ensure terminator at the end
    buffers.commandLine[commandLineBytesRead] = 0;
    if(!init_std_handles(&std_handles)) {
        send_fatal_error(hComm, GetLastError());
        close_std_handles(&std_handles);
        return false;
    }

    if(!create_interactive_process(buffers.commandLine, &std_handles, &hProcess)) {
        // TODO: Send GLE status code
        send_fatal_error(hComm, GetLastError());
        OutputDebugStringW(L"create_interactive_process: Failed to create process");
        close_std_handles(&std_handles);
        return true; // Not a fatal error
    }

    if(!send_control(hComm, RESP_INTERACTIVE_EXECUTE_PROCESS_CREATED)) {
        return false;
    }

    // Message loop
    OVERLAPPED opStdin = {0};
    OVERLAPPED opStdout = {0};
    OVERLAPPED opStderr = {0};

    BOOL stdinPending = false;
    BOOL stdoutPending = false;
    BOOL stderrPending = false;

    DWORD exitCode = 0;
    DWORD lastError = 0;
    BOOL isFatalError = false;
    BOOL isProcessError = false;

    opStdin.hEvent = CreateEvent(NULL, true, true, NULL);
    opStdout.hEvent = CreateEvent(NULL, true, true, NULL);
    opStderr.hEvent = CreateEvent(NULL, true, true, NULL);

    control = 0;

    while(true) {
        HANDLE waitable_handles[4] = {
            hProcess, opStdin.hEvent, opStdout.hEvent, opStderr.hEvent
        };
        OutputDebugStringW(L"interactive_execute: waiting for next event");
        DWORD status = WaitForMultipleObjects(
            4, waitable_handles, false, 0xFFFFFFFF
        );
        if (status == 0) {
            // Process is terminated
            // Close everything and report the exit code
            OutputDebugStringW(L"interactive_execute: hProcess signalled");
            if(!GetExitCodeProcess(hProcess, &exitCode)) {
                // ERROR: Something went wrong
                OutputDebugStringW(L"interactive_execute: Process exited but can't get exit code");
                lastError = GetLastError();
                isProcessError = true;
                break;
            }
            CloseHandle(hProcess);
            hProcess = INVALID_HANDLE_VALUE;
            break;
        }
        else if(status == 1) {
            // stdin packet from drakshell client
            OutputDebugStringW(L"interactive_execute: stdin signalled");
            DWORD bytesRead = 0;
            DWORD bytesWritten = 0;
            if(stdinPending) {
                OutputDebugStringW(L"interactive_execute: stdin pending");
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stdin to the process
                if(!GetOverlappedResult(hComm, &opStdin, &bytesRead, false)) {
                    // ERR: Operation is still pending? Weird...
                    OutputDebugStringW(L"interactive_execute: stdin read unexpectedly pending");
                    lastError = GetLastError();
                    isFatalError = true;
                    break;
                }
                // Async stdin read only reads control byte
                if(control != REQ_BLOCK) {
                    // ERR: Possible desync or client wants to terminate process
                    // Terminate gracefully
                    OutputDebugStringW(L"interactive_execute: stdin read desync");
                    break;
                }
                if(!recv_block(hComm, buffers.stdinBuffer, (LPWORD)&bytesRead, sizeof(buffers.stdinBuffer))) {
                    // ERR: Failed to read block
                    lastError = GetLastError();
                    isFatalError = true;
                    OutputDebugStringW(L"interactive_execute: stdin read failed");
                    break;
                }
                if(!WriteFile(
                    hComm, buffers.stdinBuffer, bytesRead, &bytesWritten, NULL
                )) {
                    // ERR: Failed to write to stdin
                    lastError = GetLastError();
                    isProcessError = true;
                    OutputDebugStringW(L"interactive_execute: stdin write failed");
                    break;
                }
            }
            if(!ReadFile(hComm, &control, 1, NULL, &opStdin)) {
                if(GetLastError() == ERROR_IO_PENDING) {
                    stdinPending = true;
                } else {
                    // ERROR: Read failed
                    lastError = GetLastError();
                    isFatalError = true;
                    OutputDebugStringW(L"interactive_execute: stdin read failed");
                    break;
                }
            } else {
                // Result was immediately available
                // I hope the object is signaled in that case
                // and we can just handle it in another loop
                // TODO: I need to test it by sending 1-byte stdin packets in one block
                OutputDebugStringW(L"interactive_execute: got stdin immediately");
                stdinPending = true;
            }
            OutputDebugStringW(L"interactive_execute: stdin handled");
        }
        else if (status == 2) {
            OutputDebugStringW(L"interactive_execute: stdout signalled");
            DWORD bytesRead = 0;
            DWORD bytesWritten = 0;
            // stdout packet from process
            if(stdoutPending) {
                OutputDebugStringW(L"interactive_execute: stdout pending");
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stdout to the client
                if(!GetOverlappedResult(std_handles.hStdoutRead, &opStdout, &bytesRead, false)) {
                    // ERR: Operation is still pending? Weird...
                    lastError = GetLastError();
                    isFatalError = true;
                    OutputDebugStringW(L"interactive_execute: stdout read unexpectedly pending");
                    break;
                }
                if(!send_control(hComm, RESP_STDOUT_BLOCK)) {
                    // ERR: Failed to send control byte
                    // TODO: Have dedicated control byte for STDOUT
                    lastError = GetLastError();
                    isFatalError = true;
                    OutputDebugStringW(L"interactive_execute: stdout write failed");
                    break;
                }
                if(!send_block(hComm, buffers.stdoutBuffer, (WORD)bytesRead)) {
                    // ERR: Failed to send block
                    lastError = GetLastError();
                    isFatalError = true;
                    OutputDebugStringW(L"interactive_execute: stdout write failed");
                    break;
                }
            }
            if(!ReadFile(std_handles.hStdoutRead, buffers.stdoutBuffer, sizeof(buffers.stdoutBuffer), NULL, &opStdout)) {
                if(GetLastError() == ERROR_IO_PENDING) {
                    stdoutPending = true;
                } else {
                    // ERROR: Read failed
                    lastError = GetLastError();
                    isProcessError = true;
                    OutputDebugStringW(L"interactive_execute: stdout read failed");
                    break;
                }
            } else {
                // Result was immediately available
                // I hope the object is signaled in that case
                // and we can just handle it in another loop
                stdoutPending = true;
                OutputDebugStringW(L"interactive_execute: got stdout immediately");
            }
            OutputDebugStringW(L"interactive_execute: stdout handled");
        }
        else if (status == 3) {
            OutputDebugStringW(L"interactive_execute: stderr signalled");
            DWORD bytesRead = 0;
            DWORD bytesWritten = 0;
            // stderr packet from process
            if(stderrPending) {
                OutputDebugStringW(L"interactive_execute: stderr pending");
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stderr to the client
                if(!GetOverlappedResult(std_handles.hStderrRead, &opStderr, &bytesRead, false)) {
                    // ERR: Operation is still pending? Weird...
                    lastError = GetLastError();
                    isFatalError = true;
                    OutputDebugStringW(L"interactive_execute: stderr read unexpectedly pending");
                    break;
                }
                if(!send_control(hComm, RESP_STDERR_BLOCK)) {
                    // ERR: Failed to send control byte
                    // TODO: Have dedicated control byte for STDERR
                    lastError = GetLastError();
                    isFatalError = true;
                    OutputDebugStringW(L"interactive_execute: stderr write failed");
                    break;
                }
                if(!send_block(hComm, buffers.stderrBuffer, (WORD)bytesRead)) {
                    // ERR: Failed to send block
                    lastError = GetLastError();
                    isFatalError = true;
                    OutputDebugStringW(L"interactive_execute: stderr write failed");
                    break;
                }
            }
            if(!ReadFile(std_handles.hStderrRead, buffers.stderrBuffer, sizeof(buffers.stderrBuffer), NULL, &opStderr)) {
                if(GetLastError() == ERROR_IO_PENDING) {
                    stderrPending = true;
                } else {
                    // ERROR: Read failed
                    OutputDebugStringW(L"interactive_execute: stderr read failed");
                    lastError = GetLastError();
                    isProcessError = true;
                    break;
                }
            } else {
                // Result was immediately available
                // I hope the object is signaled in that case
                // and we can just handle it in another loop
                stderrPending = true;
                OutputDebugStringW(L"interactive_execute: got stderr immediately");
            }
            OutputDebugStringW(L"interactive_execute: stderr handled");
        }
        else {
            // something went wrong
            // Terminate process, close everything and report the fatal error
            lastError = GetLastError();
            isProcessError = true;
            OutputDebugStringW(L"interactive_execute: WaitForMultipleObjects unexpected status");
            break;
        }
    }
    if(hProcess != INVALID_HANDLE_VALUE) {
        // Process is not yet closed, needs to be terminated
        OutputDebugStringW(L"interactive_execute: terminating process with ERROR_BROKEN_PIPE");
        TerminateProcess(hProcess, ERROR_BROKEN_PIPE);
    }
    if(stdinPending) {
        CancelIo(hComm);
    }
    if(stdoutPending) {
        CancelIo(std_handles.hStdoutRead);
    }
    if(stderrPending) {
        CancelIo(std_handles.hStderrRead);
    }
    close_std_handles(&std_handles);
    CloseHandle(opStdin.hEvent);
    CloseHandle(opStdout.hEvent);
    CloseHandle(opStderr.hEvent);
    if(isFatalError) {
        send_fatal_error(hComm, lastError);
        OutputDebugStringW(L"interactive_execute: fatal error");
        return false;
    } else if(isProcessError) {
        // Report process error
        send_fatal_error(hComm, lastError);
        OutputDebugStringW(L"interactive_execute: process error");
        return true;
    } else {
        // Report success
        send_control_with_code(hComm, RESP_INTERACTIVE_EXECUTE_END, exitCode);
        OutputDebugStringW(L"interactive_execute: finished successfully");
        return true;
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
        FILE_FLAG_OVERLAPPED,
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