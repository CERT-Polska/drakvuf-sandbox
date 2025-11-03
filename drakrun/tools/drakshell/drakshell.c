// gcc  headless.c
// objcopy -O binary --only-section=.text a.out out_objcopy_onlysection
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nt_loader.h"

#define REQ_PING 0xA0
#define REQ_GET_INFO 0xA1
#define REQ_INTERACTIVE_EXECUTE 0xA2
#define REQ_NON_INTERACTIVE_EXECUTE 0xA3
#define REQ_EXECUTE_AND_FINISH 0xA4
#define REQ_FINISH 0xA5
#define REQ_DATA 0xA6
#define REQ_TERMINATE_PROCESS 0xA7

#define RESP_PONG 0xA0
#define RESP_INFO 0xA1
#define RESP_INTERACTIVE_EXECUTE_START 0xA2
#define RESP_NON_INTERACTIVE_EXECUTE_START 0xA3
#define RESP_EXECUTE_AND_FINISH_START 0xA4
#define RESP_FINISH_START 0xA5
#define RESP_STDOUT_DATA 0xA6
#define RESP_STDERR_DATA 0xA7
#define RESP_PROCESS_START 0xA8
#define RESP_PROCESS_EXIT 0xA9

#define RESP_BAD_REQ 0xB0
#define RESP_FATAL_ERROR 0xB1
#define RESP_PROCESS_ERROR 0xB2

static bool read(HANDLE hComm, LPBYTE buffer, LPDWORD size, DWORD maxSize) {
    // Synchronized wrapper over async ReadFile
    OVERLAPPED overlapped = {0};
    DWORD result;
    overlapped.hEvent = CreateEvent(NULL, true, true, NULL);
    if(!ReadFile(hComm, buffer, maxSize, NULL, &overlapped)) {
        if(GetLastError() != ERROR_IO_PENDING) {
            return false;
        }
        while(true) {
            // Schedule that thread on CPU from time to time
            result = WaitForSingleObject(overlapped.hEvent, 50);
            if(!result) {
                // Signalled
                break;
            }
            else if(result != WAIT_TIMEOUT)
            {
                // Not a WAIT_OBJECT_0 and WAIT_TIMEOUT
                return false;
            }
        }
    }
    if(!GetOverlappedResult(hComm, &overlapped, size, false)) {
        return false;
    }
    return true;
}

static bool write(HANDLE hComm, LPBYTE buffer, LPDWORD size, DWORD maxSize) {
    // Synchronized wrapper over async WriteFile
    OVERLAPPED overlapped = {0};
    DWORD result;
    overlapped.hEvent = CreateEvent(NULL, true, true, NULL);
    if(!WriteFile(hComm, buffer, maxSize, NULL, &overlapped)) {
        if(GetLastError() != ERROR_IO_PENDING) {
            return false;
        }
        while(true) {
            // Schedule that thread on CPU from time to time
            result = WaitForSingleObject(overlapped.hEvent, 50);
            if(!result) {
                // Signalled
                break;
            }
            else if(result != WAIT_TIMEOUT)
            {
                // Not a WAIT_OBJECT_0 and WAIT_TIMEOUT
                return false;
            }
        }
    }
    if(!GetOverlappedResult(hComm, &overlapped, size, false)) {
        return false;
    }
    return true;
}

static bool recvn(HANDLE hComm, LPBYTE buffer, DWORD size) {
    OVERLAPPED overlapped = {0};
    DWORD bytesRead = 0;

    while(size > 0) {
        if(!read(hComm, buffer, &bytesRead, size)) {
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
        if(!write(hComm, buffer, &bytesWritten, size)) {
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

static bool recv_data(HANDLE hComm, LPBYTE bufferToRecv, LPWORD argSize, WORD argMaxSize) {
    if(!recvn(hComm, (LPBYTE)argSize, sizeof(*argSize))) {
        return false;
    }
    if(*argSize > argMaxSize) {
        OutputDebugStringW(L"recv_data: Buffer overflow");
        return false;
    }
    return recvn(hComm, bufferToRecv, *argSize);
}

static bool send_data(HANDLE hComm, LPBYTE bufferToSend, WORD argSize) {
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

static bool recv_data_to_void(HANDLE hComm) {
    BYTE buffer[1024];
    WORD bytesRead;
    return recv_data(hComm, buffer, &bytesRead, sizeof(buffer));
}

typedef struct _STD_HANDLES {
    HANDLE hStdinRead;
    HANDLE hStdinWrite;
    HANDLE hStdoutRead;
    HANDLE hStdoutWrite;
    HANDLE hStderrRead;
    HANDLE hStderrWrite;
} STD_HANDLES, *PSTD_HANDLES;


static void close_std_handles(PSTD_HANDLES handles) {
    DWORD gle = GetLastError();
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
    // This is a common cleanup function and we don't want to
    // overwrite GLE coming from the faulting function
    SetLastError(gle);
}

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
        close_std_handles(handles);
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
        close_std_handles(handles);
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
        close_std_handles(handles);
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
        close_std_handles(handles);
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
        close_std_handles(handles);
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
        close_std_handles(handles);
        return false;
    }

    return true;
}

static bool create_process(LPWSTR szCmdline, PSTD_HANDLES std_handles, PHANDLE lphProcess) {
    BOOL bSuccess;
    PROCESS_INFORMATION piProcInfo = {0};
    STARTUPINFOW siStartInfo = {0};

    siStartInfo.cb = sizeof(STARTUPINFOW);

    if(std_handles != NULL) {
        if(!init_std_handles(std_handles)) {
            return false;
        }
        siStartInfo.hStdError = std_handles->hStderrWrite;
        siStartInfo.hStdOutput = std_handles->hStdoutWrite;
        siStartInfo.hStdInput = std_handles->hStdinRead;
        siStartInfo.dwFlags = STARTF_USESTDHANDLES;
    }

    bSuccess = CreateProcessW(NULL,
        szCmdline,           // command line
        NULL,                // process security attributes
        NULL,                // primary thread security attributes
        std_handles != NULL, // handles are inherited if interaction is needed
        0,                   // creation flags
        NULL,                // use parent's environment
        NULL,                // use parent's current directory
        &siStartInfo,        // STARTUPINFO pointer
        &piProcInfo          // receives PROCESS_INFORMATION
    );
    if(!bSuccess) {
        if(std_handles != NULL)
            close_std_handles(std_handles);
        return false;
    } else {
        // Close handle to the main thread
        CloseHandle(piProcInfo.hThread);
        // Close handles to the child-side of pipes
        // because inheritance made a duplicates
        if(std_handles != NULL) {
            CloseHandle(std_handles->hStderrWrite);
            std_handles->hStderrWrite = INVALID_HANDLE_VALUE;
            CloseHandle(std_handles->hStdoutWrite);
            std_handles->hStdoutWrite = INVALID_HANDLE_VALUE;
            CloseHandle(std_handles->hStdinRead);
            std_handles->hStdinRead = INVALID_HANDLE_VALUE;
        }
        // Pass process handle to the caller
        if(lphProcess != NULL) {
            *lphProcess = piProcInfo.hProcess;
        } else {
            CloseHandle(piProcInfo.hProcess);
        }
        return true;
    }
}

static bool process_execute(HANDLE hComm, BOOL interactive) {
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
    if(control != REQ_DATA) {
        // We probably lost sync in the middle
        // and there is another try to use drakshell.
        // Let's finish this mode gracefully
        if(!send_control(hComm, RESP_BAD_REQ)) {
            return false;
        }
        return true;
    }
    if(!recv_data(hComm, (LPBYTE)buffers.commandLine, &commandLineBytesRead, sizeof(buffers.commandLine) - sizeof(wchar_t))) {
        send_control(hComm, RESP_BAD_REQ);
        return false;
    }
    // Ensure terminator at the end
    buffers.commandLine[commandLineBytesRead] = 0;

    if(!create_process(buffers.commandLine, interactive ? &std_handles : NULL, interactive ? &hProcess : NULL)) {
        send_control_with_code(hComm, RESP_PROCESS_ERROR, GetLastError());
        OutputDebugStringW(L"process_execute: Failed to create process");
        return true; // Not a fatal error
    }

    if(!send_control(hComm, RESP_PROCESS_START)) {
        return false;
    }

    if(!interactive) {
        // Process started and we don't have to wait
        // Finish successfully
        return true;
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

    #define LOOP_BREAK_FATAL_ERROR 1
    #define LOOP_BREAK_BROKEN_PIPE 2
    #define LOOP_BREAK_PROCESS_EXIT 3
    #define LOOP_BREAK_KILL_PROCESS 4
    #define LOOP_BREAK_BAD_REQUEST 5

    DWORD loopBreakReason = 0;

    opStdin.hEvent = CreateEvent(NULL, true, true, NULL);
    opStdout.hEvent = CreateEvent(NULL, true, true, NULL);
    opStderr.hEvent = CreateEvent(NULL, true, true, NULL);

    control = 0;

    while(true) {
        /**
         * Loop that is waiting for the following signals:
         *
         * 0 - Process termination
         * 1 - Input from drakshell client
         *     - stdin
         *     - termination request
         * 2 - Stdout from process
         * 3 - Stderr from process
         */
        HANDLE waitable_handles[4] = {
            hProcess, opStdin.hEvent, opStdout.hEvent, opStderr.hEvent
        };
        DWORD status = WaitForMultipleObjects(
            4, waitable_handles, false, 50
        );
        if (status == 0) {
            // Process is terminated
            // Close everything and report the exit code
            OutputDebugStringW(L"process_execute: hProcess signalled");
            if(!GetExitCodeProcess(hProcess, &exitCode)) {
                OutputDebugStringW(L"process_execute: Process exited but can't get exit code");
                lastError = GetLastError();
                loopBreakReason = LOOP_BREAK_BROKEN_PIPE;
                break;
            } else {
                loopBreakReason = LOOP_BREAK_PROCESS_EXIT;
            }
            CloseHandle(hProcess);
            hProcess = INVALID_HANDLE_VALUE;
            break;
        }
        else if(status == 1) {
            // stdin packet from drakshell client
            OutputDebugStringW(L"process_execute: stdin signalled");
            DWORD bytesRead = 0;
            DWORD bytesWritten = 0;
            if(stdinPending) {
                OutputDebugStringW(L"process_execute: stdin pending");
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stdin to the process
                if(!GetOverlappedResult(hComm, &opStdin, &bytesRead, false)) {
                    // ERR: Operation is still pending? Weird...
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stdin read broken pipe");
                    loopBreakReason = LOOP_BREAK_FATAL_ERROR;
                    break;
                }
                // Async stdin read only reads control byte
                if(control == REQ_DATA) {
                    if(!recv_data(hComm, buffers.stdinBuffer, (LPWORD)&bytesRead, sizeof(buffers.stdinBuffer))) {
                        // ERR: Failed to read block
                        lastError = GetLastError();
                        OutputDebugStringW(L"process_execute: stdin read failed");
                        loopBreakReason = LOOP_BREAK_FATAL_ERROR;
                        break;
                    }
                    if(!sendn(
                        std_handles.hStdinWrite, buffers.stdinBuffer, bytesRead
                    )) {
                        // ERR: Failed to write to stdin
                        lastError = GetLastError();
                        OutputDebugStringW(L"process_execute: stdin write failed");
                        loopBreakReason = LOOP_BREAK_BROKEN_PIPE;
                        break;
                    }
                }
                else if(control == REQ_TERMINATE_PROCESS) {
                    // Terminate gracefully
                    loopBreakReason = LOOP_BREAK_KILL_PROCESS;
                    break;
                }
                else {
                    // Unknown control
                    loopBreakReason = LOOP_BREAK_BAD_REQUEST;
                    break;
                }
            }
            if(!ReadFile(hComm, &control, 1, NULL, &opStdin)) {
                if(GetLastError() == ERROR_IO_PENDING) {
                    stdinPending = true;
                } else {
                    // ERROR: Read failed
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stdin read failed");
                    loopBreakReason = LOOP_BREAK_FATAL_ERROR;
                    break;
                }
            } else {
                OutputDebugStringW(L"process_execute: got stdin immediately");
                stdinPending = true;
            }
            OutputDebugStringW(L"process_execute: stdin handled");
        }
        else if (status == 2) {
            OutputDebugStringW(L"process_execute: stdout signalled");
            DWORD bytesRead = 0;
            DWORD bytesWritten = 0;
            // stdout packet from process
            if(stdoutPending) {
                OutputDebugStringW(L"process_execute: stdout pending");
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stdout to the client
                if(!GetOverlappedResult(std_handles.hStdoutRead, &opStdout, &bytesRead, false)) {
                    // ERR: Operation is still pending? Weird...
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stdout read broken pipe");
                    loopBreakReason = LOOP_BREAK_BROKEN_PIPE;
                    break;
                }
                if(!send_control(hComm, RESP_STDOUT_DATA)) {
                    // ERR: Failed to send control byte
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stdout write failed");
                    loopBreakReason = LOOP_BREAK_FATAL_ERROR;
                    break;
                }
                if(!send_data(hComm, buffers.stdoutBuffer, (WORD)bytesRead)) {
                    // ERR: Failed to send block
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stdout write failed");
                    loopBreakReason = LOOP_BREAK_FATAL_ERROR;
                    break;
                }
            }
            if(!ReadFile(std_handles.hStdoutRead, buffers.stdoutBuffer, sizeof(buffers.stdoutBuffer), NULL, &opStdout)) {
                if(GetLastError() == ERROR_IO_PENDING) {
                    stdoutPending = true;
                } else {
                    // ERROR: Read failed
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stdout read failed");
                    loopBreakReason = LOOP_BREAK_BROKEN_PIPE;
                    break;
                }
            } else {
                // Result was immediately available
                // I hope the object is signaled in that case
                // and we can just handle it in another loop
                OutputDebugStringW(L"process_execute: got stdout immediately");
                stdoutPending = true;
            }
            OutputDebugStringW(L"process_execute: stdout handled");
        }
        else if (status == 3) {
            OutputDebugStringW(L"process_execute: stderr signalled");
            DWORD bytesRead = 0;
            DWORD bytesWritten = 0;
            // stderr packet from process
            if(stderrPending) {
                OutputDebugStringW(L"process_execute: stderr pending");
                // Pending operation finished
                // Call GetOverlappedResult to get the size
                // Then send the stderr to the client
                if(!GetOverlappedResult(std_handles.hStderrRead, &opStderr, &bytesRead, false)) {
                    // ERR: Operation is still pending? Weird...
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stderr read broken pipe");
                    loopBreakReason = LOOP_BREAK_BROKEN_PIPE;
                    break;
                }
                if(!send_control(hComm, RESP_STDERR_DATA)) {
                    // ERR: Failed to send control byte
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stderr write failed");
                    loopBreakReason = LOOP_BREAK_FATAL_ERROR;
                    break;
                }
                if(!send_data(hComm, buffers.stderrBuffer, (WORD)bytesRead)) {
                    // ERR: Failed to send block
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stderr write failed");
                    loopBreakReason = LOOP_BREAK_FATAL_ERROR;
                    break;
                }
            }
            if(!ReadFile(std_handles.hStderrRead, buffers.stderrBuffer, sizeof(buffers.stderrBuffer), NULL, &opStderr)) {
                if(GetLastError() == ERROR_IO_PENDING) {
                    stderrPending = true;
                } else {
                    // ERROR: Read failed
                    lastError = GetLastError();
                    OutputDebugStringW(L"process_execute: stderr read failed");
                    loopBreakReason = LOOP_BREAK_BROKEN_PIPE;
                    break;
                }
            } else {
                // Result was immediately available
                // I hope the object is signaled in that case
                // and we can just handle it in another loop
                stderrPending = true;
                OutputDebugStringW(L"process_execute: got stderr immediately");
            }
            OutputDebugStringW(L"process_execute: stderr handled");
        }
        else if (status == WAIT_TIMEOUT) {
            continue;
        }
        else {
            // something went wrong
            // Terminate process, close everything and report the fatal error
            lastError = GetLastError();
            OutputDebugStringW(L"process_execute: WaitForMultipleObjects unexpected status");
            loopBreakReason = LOOP_BREAK_BROKEN_PIPE;
            break;
        }
    }

    if(hProcess != INVALID_HANDLE_VALUE) {
        // Process is not terminated or it has unknown status
        if(LOOP_BREAK_BROKEN_PIPE == loopBreakReason ||
           LOOP_BREAK_PROCESS_EXIT == loopBreakReason)
        {
            // Wait a while for process to stop
            WaitForSingleObject(hProcess, 1000);
        }
        if(!GetExitCodeProcess(hProcess, &exitCode))
        {
            // Process is not yet closed, needs to be terminated
            OutputDebugStringW(L"process_execute: terminating process with ERROR_BROKEN_PIPE");
            TerminateProcess(hProcess, ERROR_BROKEN_PIPE);
            exitCode = ERROR_BROKEN_PIPE;
        }
        CloseHandle(hProcess);
        hProcess = INVALID_HANDLE_VALUE;
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

    if(LOOP_BREAK_FATAL_ERROR == loopBreakReason) {
        send_fatal_error(hComm, lastError);
        OutputDebugStringW(L"interactive_execute: fatal error");
        return false;
    }
    else if(LOOP_BREAK_BROKEN_PIPE == loopBreakReason ||
            LOOP_BREAK_PROCESS_EXIT == loopBreakReason ||
            LOOP_BREAK_KILL_PROCESS == loopBreakReason ||
            LOOP_BREAK_BAD_REQUEST == loopBreakReason)
    {
        // Report process exit
        send_control_with_code(hComm, RESP_PROCESS_EXIT, exitCode);
        OutputDebugStringW(L"interactive_execute: finished successfully");
        return true;
    }
}

static bool send_info(HANDLE hComm) {
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    if(!sendn(hComm, (LPBYTE)&pid, sizeof(pid))) {
        return false;
    }
    if(!sendn(hComm, (LPBYTE)&tid, sizeof(tid))) {
        return false;
    }
    return true;
}

void __attribute__((noinline)) __attribute__((ms_abi)) drakshell_loop(HANDLE hComm) {
    // Initialize COM to allow injected ShellExecute calls
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

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
        else if(control == REQ_GET_INFO) {
            if(!send_control(hComm, RESP_INFO)) {
                OutputDebugStringW(L"Failed to send RESP_INFO response");
                break;
            }
            if(!send_info(hComm)) {
                OutputDebugStringW(L"Failed to send INFO response");
                break;
            }
        }
        else if(control == REQ_INTERACTIVE_EXECUTE) {
            if(!send_control(hComm, RESP_INTERACTIVE_EXECUTE_START)) {
                OutputDebugStringW(L"Failed to send RESP_INTERACTIVE_EXECUTE_START response");
                break;
            }
            if(!process_execute(hComm, true)) {
                OutputDebugStringW(L"Fatal error in interactive execute mode");
                break;
            }
        }
        else if(control == REQ_NON_INTERACTIVE_EXECUTE) {
            if(!send_control(hComm, RESP_NON_INTERACTIVE_EXECUTE_START)) {
                OutputDebugStringW(L"Failed to send RESP_INTERACTIVE_EXECUTE_START response");
                break;
            }
            if(!process_execute(hComm, false)) {
                OutputDebugStringW(L"Fatal error in non-interactive execute mode");
                break;
            }
        }
        else if(control == REQ_EXECUTE_AND_FINISH) {
            if(!send_control(hComm, RESP_EXECUTE_AND_FINISH_START)) {
                OutputDebugStringW(L"Failed to send RESP_INTERACTIVE_EXECUTE_START response");
                break;
            }
            if(!process_execute(hComm, false)) {
                OutputDebugStringW(L"Fatal error in execute-and-finish mode");
            }
            // We're always finishing here
            break;
        }
        else if(control == REQ_FINISH) {
            if(!send_control(hComm, RESP_FINISH_START)) {
                OutputDebugStringW(L"Failed to send RESP_FINISH_START response");
            }
            break;
        }
        else if(control == REQ_DATA) {
            // We're definitely out of sync, but we need to consume
            // what client wants to serve
            if(!recv_data_to_void(hComm)) {
                OutputDebugStringW(L"Failed to receive REQ_DATA");
                break;
            }
            if(!send_control(hComm, RESP_BAD_REQ)) {
                OutputDebugStringW(L"Failed to send RESP_BAD_REQ response");
                break;
            }
        }
        else {
            if(!send_control(hComm, RESP_BAD_REQ)) {
                OutputDebugStringW(L"Failed to send RESP_BAD_REQ response");
                break;
            }
        }
    }
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

    if(!BuildCommDCB("baud=115200 parity=N data=8 stop=1", &dcb))
    {
        OutputDebugStringW(L"Failed to get DCB for COM1");
        return;
    }

    if(!SetCommState(hComm, &dcb))
    {
        OutputDebugStringW(L"Failed to set mode of COM1");
        return;
    }

    OutputDebugStringW(L"Connected to COM1");

	// It's convenient to wrap the loop in separate thread.
	// Drakvuf can signal end of injection by exiting it
	// via --exit-injection-thread. This enables us to clean up
	// the shellcode from the memory after the drakshell_loop is terminated
	HANDLE hThread = CreateThread(
        NULL, 0,
        drakshell_loop,
        (void*)hComm,
        0, NULL
    );
    WaitForSingleObject(hThread, (DWORD)-1);
	CloseHandle(hThread);

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
