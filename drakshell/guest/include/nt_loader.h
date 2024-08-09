#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if __SIZEOF_WCHAR_T__ != 2
#error "wchar_t is not two-byte, please compile with -fshort-wchar"
#endif

#define GENERIC_WRITE 0x40000000
#define GENERIC_READ  0x80000000
#define OPEN_EXISTING 3
#define CREATE_NEW 1
#define INVALID_HANDLE_VALUE ((void*)(long long)-1)
#define HANDLE_FLAG_INHERIT 1
#define STARTF_USESTDHANDLES 0x00000100
#define ERROR_IO_PENDING 0x000003e5
#define ERROR_BROKEN_PIPE 0x0000006d
#define PIPE_ACCESS_DUPLEX 0x00000003
#define PIPE_ACCESS_OUTBOUND 0x00000002
#define PIPE_ACCESS_INBOUND 0x00000001
#define FILE_FLAG_OVERLAPPED 0x40000000
#define FILE_FLAG_FIRST_PIPE_INSTANCE 0x00080000
#define INFINITE 0xffffffff

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;

typedef uint8_t * PBYTE, * LPBYTE;
typedef uint16_t * PWORD, * LPWORD;
typedef uint32_t * PDWORD, * LPDWORD;
typedef uint64_t * PQWORD, * LPQWORD;

typedef long LONG;
typedef unsigned long ULONG;
typedef int INT;
typedef unsigned int UINT;
typedef short SHORT;
typedef unsigned short USHORT;
typedef char CHAR;
typedef unsigned char UCHAR;

typedef void* HANDLE;
typedef void* PVOID;
typedef PVOID LPVOID;
typedef HANDLE *PHANDLE;
typedef unsigned long SIZE_T;
typedef const char* LPCSTR;
typedef const wchar_t* LPCWSTR;
typedef char* LPSTR;
typedef wchar_t* LPWSTR;
typedef bool BOOL;

typedef struct _DCB {
    DWORD DCBlength;
    DWORD BaudRate;
    DWORD fBinary : 1;
    DWORD fParity : 1;
    DWORD fOutxCtsFlow : 1;
    DWORD fOutxDsrFlow : 1;
    DWORD fDtrControl : 2;
    DWORD fDsrSensitivity : 1;
    DWORD fTXContinueOnXoff : 1;
    DWORD fOutX : 1;
    DWORD fInX : 1;
    DWORD fErrorChar : 1;
    DWORD fNull : 1;
    DWORD fRtsControl : 2;
    DWORD fAbortOnError : 1;
    DWORD fDummy2 : 17;
    WORD  wReserved;
    WORD  XonLim;
    WORD  XoffLim;
    BYTE  ByteSize;
    BYTE  Parity;
    BYTE  StopBits;
    char  XonChar;
    char  XoffChar;
    char  ErrorChar;
    char  EofChar;
    char  EvtChar;
    WORD  wReserved1;
} DCB, *LPDCB;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD  nLength;
    LPVOID lpSecurityDescriptor;
    BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOW {
    DWORD  cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD  dwX;
    DWORD  dwY;
    DWORD  dwXSize;
    DWORD  dwYSize;
    DWORD  dwXCountChars;
    DWORD  dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags;
    WORD   wShowWindow;
    WORD   cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _OVERLAPPED {
    PVOID Internal;
    PVOID InternalHigh;
    union {
        struct {
            DWORD Offset;
            DWORD OffsetHigh;
        } DUMMYSTRUCTNAME;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;

#define WINAPI __attribute__((ms_abi))

typedef int (WINAPI* PCreateThread)(
    LPVOID lpThreadAttributes,
    SIZE_T dwStackSize,
    LPVOID lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);
extern PCreateThread pCreateThread;
#define CreateThread (*pCreateThread)

typedef HANDLE (WINAPI* PLoadLibraryW)(LPCWSTR lpLibFileName);
extern PLoadLibraryW pLoadLibraryW;
#define LoadLibraryW (*pLoadLibraryW)

typedef HANDLE (WINAPI* PGetProcAddress)(HANDLE hModule, LPCSTR lpProcName);
extern PGetProcAddress pGetProcAddress;
#define GetProcAddress (*pGetProcAddress)

typedef int (WINAPI* PMessageBoxA)(HANDLE, LPCSTR, LPCSTR, UINT);
extern PMessageBoxA pMessageBoxA;
#define MessageBoxA (*pMessageBoxA)

typedef DWORD (WINAPI* PExpandEnvironmentStringsW)(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
extern PExpandEnvironmentStringsW pExpandEnvironmentStringsW;
#define ExpandEnvironmentStringsW (*pExpandEnvironmentStringsW)

typedef void (WINAPI* POutputDebugStringW)(LPCWSTR lpOutputString);
extern POutputDebugStringW pOutputDebugStringW;
#define OutputDebugStringW (*pOutputDebugStringW)

typedef bool (WINAPI* PCloseHandle)(HANDLE hObject);
extern PCloseHandle pCloseHandle;
#define CloseHandle (*pCloseHandle)

typedef BOOL (WINAPI* PCreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);
extern PCreateProcessW pCreateProcessW;
#define CreateProcessW (*pCreateProcessW)

typedef HANDLE (WINAPI* PCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPVOID lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
extern PCreateFileW pCreateFileW;
#define CreateFileW (*pCreateFileW)

typedef bool (WINAPI* PReadFile)(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPVOID lpOverlapped
);
extern PReadFile pReadFile;
#define ReadFile (*pReadFile)

typedef bool (WINAPI* PWriteFile)(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPVOID lpOverlapped
);
extern PWriteFile pWriteFile;
#define WriteFile (*pWriteFile)

typedef void (WINAPI* PExitThread)(
    DWORD dwExitCode
);
extern PExitThread pExitThread;
#define ExitThread (*pExitThread)

typedef void (WINAPI* PSleep)(
    DWORD dwMilliseconds
);
extern PSleep pSleep;
#define Sleep (*pSleep)

typedef void (WINAPI* PVirtualFree)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
);
extern PVirtualFree pVirtualFree;

typedef DWORD (WINAPI* PGetLastError)();
extern PGetLastError pGetLastError;
#define GetLastError (*pGetLastError)

typedef BOOL (WINAPI* PGetCommState)(
    HANDLE hFile,
    LPDCB  lpDCB
);
extern PGetCommState pGetCommState;
#define GetCommState (*pGetCommState)

typedef BOOL (WINAPI* PSetCommState)(
    HANDLE hFile,
    LPDCB  lpDCB
);
extern PSetCommState pSetCommState;
#define SetCommState (*pSetCommState)

typedef BOOL (WINAPI* PCreatePipe)(
    PHANDLE hReadPipe,
    PHANDLE hWritePipe,
    LPSECURITY_ATTRIBUTES lpPipeAttributes,
    DWORD nSize
);
extern PCreatePipe pCreatePipe;
#define CreatePipe (*pCreatePipe)

typedef BOOL (WINAPI* PSetHandleInformation)(
    HANDLE hObject,
    DWORD  dwMask,
    DWORD  dwFlags
);
extern PSetHandleInformation pSetHandleInformation;
#define SetHandleInformation (*pSetHandleInformation)

typedef DWORD (WINAPI* PWaitForMultipleObjects)(
    DWORD nCount,
    const HANDLE *lpHandles,
    BOOL bWaitAll,
    DWORD dwMilliseconds
);
extern PWaitForMultipleObjects pWaitForMultipleObjects;
#define WaitForMultipleObjects (*pWaitForMultipleObjects)

typedef HANDLE (WINAPI* PCreateEvent)(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL bManualReset,
    BOOL bInitialState,
    LPCSTR lpName
);
extern PCreateEvent pCreateEvent;
#define CreateEvent (*pCreateEvent)

typedef BOOL (WINAPI* PGetOverlappedResult)(
    HANDLE hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD lpNumberOfBytesTransferred,
    BOOL bWait
);
extern PGetOverlappedResult pGetOverlappedResult;
#define GetOverlappedResult (*pGetOverlappedResult)

typedef BOOL (WINAPI* PCancelIo)(
    HANDLE hFile
);
extern PCancelIo pCancelIo;
#define CancelIo (*pCancelIo)

typedef BOOL (WINAPI* PGetExitCodeProcess)(
    HANDLE hProcess,
    LPDWORD lpExitCode
);
extern PGetExitCodeProcess pGetExitCodeProcess;
#define GetExitCodeProcess (*pGetExitCodeProcess)

typedef BOOL (WINAPI* PTerminateProcess)(
    HANDLE hProcess,
    UINT uExitCode
);
extern PTerminateProcess pTerminateProcess;
#define TerminateProcess (*pTerminateProcess)

typedef HANDLE (WINAPI* PCreateNamedPipeW)(
    LPCWSTR lpName,
    DWORD dwOpenMode,
    DWORD dwPipeMode,
    DWORD nMaxInstances,
    DWORD nOutBufferSize,
    DWORD nInBufferSize,
    DWORD nDefaultTimeOut,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
extern PCreateNamedPipeW pCreateNamedPipeW;
#define CreateNamedPipe (*pCreateNamedPipeW)

typedef DWORD (WINAPI* PWaitForSingleObject)(
    HANDLE hHandle,
    DWORD  dwMilliseconds
);
extern PWaitForSingleObject pWaitForSingleObject;
#define WaitForSingleObject (*pWaitForSingleObject)

extern void* get_func_from_peb(const wchar_t* libraryName, const char* procName);
extern bool load_winapi();
