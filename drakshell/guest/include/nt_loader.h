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
typedef void* LPVOID;
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

typedef bool (WINAPI* PCreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPVOID lpProcessAttributes,
    LPVOID lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPVOID lpStartupInfo,
    LPVOID lpProcessInformation
);
extern PCreateProcessW pCreateProcessW;
#define CreateProcessW (*pCreateProcessW)

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

extern void* get_func_from_peb(const wchar_t* libraryName, const char* procName);
extern bool load_winapi();