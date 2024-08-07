// gcc  headless.c
// objcopy -O binary --only-section=.text a.out out_objcopy_onlysection
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nt_loader.h"

#define REQ_PING 0x30
#define REQ_UPLOAD 0x31
#define REQ_DOWNLOAD 0x32
#define REQ_EXIT 0x33

#define RESP_SUCCESS 0x30
#define RESP_FILE_OPENED 0x31
#define RESP_ERROR 0x32

static bool recv(HANDLE hComm, LPBYTE buffer, DWORD size) {
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

static bool send(HANDLE hComm, LPBYTE buffer, DWORD size) {
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

static bool recv_req(HANDLE hComm, LPBYTE req) {
    return recv(hComm, req, sizeof(*req));
}

static bool send_resp(HANDLE hComm, BYTE resp) {
    return send(hComm, &resp, sizeof(resp));
}

static bool send_error(HANDLE hComm) {
    DWORD gle = GetLastError();
    BYTE resp = RESP_ERROR;
    if(!send(hComm, &resp, sizeof(resp)))
        return false;
    return send(hComm, (LPBYTE)&gle, sizeof(gle));
}

static bool recv_arg(HANDLE hComm, LPBYTE bufferToRecv, LPWORD argSize, WORD argMaxSize) {
    if(!recv(hComm, (LPBYTE)argSize, sizeof(*argSize))) {
        return false;
    }
    if(*argSize > argMaxSize) {
        return false;
    }
    return recv(hComm, bufferToRecv, *argSize);
}

static bool send_arg(HANDLE hComm, LPBYTE bufferToSend, WORD argSize) {
    if(!send(hComm, (LPBYTE)&argSize, sizeof(argSize))) {
        return false;
    }
    if(!argSize)
        return true;
    return send(hComm, bufferToSend, argSize);
}

static bool req_ping(HANDLE hComm) {
    return send_resp(hComm, RESP_SUCCESS);
}

static bool req_upload_file(HANDLE hComm)
{
    union {
        struct {
            wchar_t fileName[512];
            wchar_t targetFileName[512];
        };
        BYTE buffer[4096];
    } buffers;
    WORD readBytes = 0;
    // Receive file name
    if(!recv_arg(hComm, (LPBYTE)buffers.fileName, &readBytes, sizeof(buffers.fileName) - sizeof(wchar_t))) {
        return false;
    }
    // Ensure terminator at the end
    buffers.fileName[readBytes] = 0;
    // Expand into target file name
    DWORD maxTargetSize = (sizeof(buffers.targetFileName) / sizeof(wchar_t));
    DWORD targetSize = ExpandEnvironmentStringsW(buffers.fileName, buffers.targetFileName, maxTargetSize);
    if(!targetSize || targetSize > maxTargetSize) {
        send_error(hComm);
        return true;
    }
    // Try to open file for writing
    HANDLE hFile = CreateFileW(
        buffers.targetFileName,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_NEW,
        0,
        NULL
    );
    if(hFile == INVALID_HANDLE_VALUE) {
        send_error(hComm);
        return true;
    }
    // If everything is OK so far, let client continue its upload
    if(!send_resp(hComm, RESP_FILE_OPENED)) {
        CloseHandle(hFile);
        return false;
    }
    if(!send_arg(hComm, (LPBYTE)buffers.targetFileName, targetSize * sizeof(wchar_t))) {
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesWritten;

    while(true) {
        if(!recv_arg(hComm, buffers.buffer, &readBytes, sizeof(buffers.buffer))) {
            CloseHandle(hFile);
            return false;
        }
        if(readBytes == 0) {
            break;
        }
        if(!WriteFile(hFile, buffers.buffer, readBytes, &bytesWritten, NULL)) {
            send_error(hComm);
            CloseHandle(hFile);
            return true;
        }
    }
    send_resp(hComm, RESP_SUCCESS);
    CloseHandle(hFile);
    return true;
}

static bool req_download_file(HANDLE hComm)
{
    union {
        struct {
            wchar_t fileName[512];
            wchar_t targetFileName[512];
        };
        BYTE buffer[4096];
    } buffers;
    WORD readBytes = 0;
    // Receive file name
    if(!recv_arg(hComm, (LPBYTE)buffers.fileName, &readBytes, sizeof(buffers.fileName) - sizeof(wchar_t))) {
        return false;
    }
    // Ensure terminator at the end
    buffers.fileName[readBytes] = 0;
    // Expand into target file name
    DWORD maxTargetSize = (sizeof(buffers.targetFileName) / sizeof(wchar_t));
    DWORD targetSize = ExpandEnvironmentStringsW(buffers.fileName, buffers.targetFileName, maxTargetSize);
    if(!targetSize || targetSize > maxTargetSize) {
        send_error(hComm);
        return true;
    }
    // Try to open file for writing
    HANDLE hFile = CreateFileW(
        buffers.targetFileName,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if(hFile == INVALID_HANDLE_VALUE) {
        send_error(hComm);
        return true;
    }
    // If everything is OK so far, let client continue its upload
    if(!send_resp(hComm, RESP_FILE_OPENED)) {
        CloseHandle(hFile);
        return false;
    }
    if(!send_arg(hComm, (LPBYTE)buffers.targetFileName, targetSize * sizeof(wchar_t))) {
        CloseHandle(hFile);
        return false;
    }

    DWORD readBytesFromFile;

    while(true) {
        if(!ReadFile(hFile, buffers.buffer, sizeof(buffers.buffer), &readBytesFromFile, NULL)) {
            send_arg(hComm, NULL, 0); // send EOF
            send_error(hComm); // then reading error
            CloseHandle(hFile);
            return true;
        }
        if(!send_arg(hComm, buffers.buffer, readBytesFromFile)) {
            CloseHandle(hFile);
            return false;
        }
        if(readBytes == 0) {
            // EOF has been sent, we can break the loop
            break;
        }
    }
    send_resp(hComm, RESP_SUCCESS);
    CloseHandle(hFile);
    return true;
}

void __attribute__((noinline)) __attribute__((force_align_arg_pointer)) drakshell_main() {
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

    OutputDebugStringW(L"I'm connected");

    while(true) {
        BYTE command = 0;

        if(!recv(hComm, &command, 1)) {
            break;
        }

        if(command == REQ_PING) {
            if(!req_ping(hComm))
                break;
        }
        else if(command == REQ_UPLOAD) {
            if(!req_upload_file(hComm))
                break;
        }
        else if(command == REQ_DOWNLOAD) {
            if(!req_download_file(hComm))
                break;
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