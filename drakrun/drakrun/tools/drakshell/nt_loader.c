#include "nt_loader.h"

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
    uint8_t Reserved1[8];
    void* Reserved2[2];
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    uint8_t Reserved1[2];
    uint8_t BeingDebugged;
    uint8_t Reserved2[1];
    void* Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _UNICODE_STRING
{
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitOrderModuleList;
    void* DllBase;
    void* EntryPoint;
    void* Reserved3;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_DOS_HEADER
{
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    void* ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    void* SizeOfStackReserve;
    void* SizeOfStackCommit;
    void* SizeOfHeapReserve;
    void* SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

typedef struct _IMAGE_EXPORT_DIRECTORY {
     uint32_t Characteristics;
     uint32_t TimeDateStamp;
     uint16_t MajorVersion;
     uint16_t MinorVersion;
     uint32_t Name;
     uint32_t Base;
     uint32_t NumberOfFunctions;
     uint32_t NumberOfNames;
     uint32_t AddressOfFunctions;
     uint32_t AddressOfNames;
     uint32_t AddressOfNameOrdinals;
 } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#define container_of(ptr, type, member) ({ \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type, member) );})

static PPEB get_peb() {
    volatile PPEB peb;
    #if defined(__x86_64__)
        asm("mov %0, gs:[0x60]" : "=r"(peb));
    #endif
    #if defined(__i386__)
        asm("mov %0, fs:[0x30]" : "=r"(peb));
    #endif
    return peb;
}

static wchar_t lowercase(wchar_t c) {
    return (c >='A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

static bool unicode_string_equals(PUNICODE_STRING unicodeString, const wchar_t* value) {
    uint16_t current_length = unicodeString->Length / 2; // without null-byte
    wchar_t* current_char = unicodeString->Buffer;
    while(current_length > 0 && *value != 0) {
        if(lowercase(*value) != lowercase(*current_char))
            return false;
        value++;
        current_char++;
        current_length--;
    }
    return current_length == 0 && *value == 0;
}

static int strcmp(const char* s1, const char* s2)
{
    while(*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

void* get_func_from_peb(const wchar_t* libraryName, const char* procName)
{
    PPEB peb = get_peb();
    PLIST_ENTRY module_entry = peb->Ldr->InMemoryOrderModuleList.Flink;
    while(module_entry) {
        PLDR_DATA_TABLE_ENTRY module = container_of(module_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if(unicode_string_equals(&module->BaseDllName, libraryName))
        {
            void* DllBase = module->DllBase;
            PIMAGE_NT_HEADERS pDLL = DllBase + ((PIMAGE_DOS_HEADER)module->DllBase)->e_lfanew;
            uint32_t exportsRVA = pDLL->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY exportsDir = DllBase + exportsRVA;
            uint32_t* names_rva_array = (uint32_t*) (DllBase + exportsDir->AddressOfNames);
            uint32_t* function_rva_array = (uint32_t*) (DllBase + exportsDir->AddressOfFunctions);
            uint16_t* name_ordinals_array = (uint16_t*) (DllBase + exportsDir->AddressOfNameOrdinals);
            for(int i=0; i<exportsDir->NumberOfFunctions; ++i) {
                char* funct_name = DllBase + names_rva_array[i];
                uint32_t exported_RVA = function_rva_array[name_ordinals_array[i]];

                if(!strcmp(procName, funct_name)) {
                    return (void*) (DllBase + exported_RVA);
                }
            }
            return NULL;
        }
        module_entry = module_entry->Flink;
    }
    return NULL;
}

PLoadLibraryW pLoadLibraryW;
PGetProcAddress pGetProcAddress;
PMessageBoxA pMessageBoxA;
PExpandEnvironmentStringsW pExpandEnvironmentStringsW;
POutputDebugStringW pOutputDebugStringW;
PCloseHandle pCloseHandle;
PCreateFileW pCreateFileW;
PReadFile pReadFile;
PWriteFile pWriteFile;
PCreateProcessW pCreateProcessW;
PExitThread pExitThread;
PSleep pSleep;
PVirtualFree pVirtualFree;
PGetLastError pGetLastError;
PGetCommState pGetCommState;
PSetCommState pSetCommState;
PCreatePipe pCreatePipe;
PSetHandleInformation pSetHandleInformation;
PWaitForMultipleObjects pWaitForMultipleObjects;
PCreateEvent pCreateEvent;
PGetOverlappedResult pGetOverlappedResult;
PCancelIo pCancelIo;
PGetExitCodeProcess pGetExitCodeProcess;
PTerminateProcess pTerminateProcess;
PCreateNamedPipeW pCreateNamedPipeW;
PWaitForSingleObject pWaitForSingleObject;
PSetLastError pSetLastError;
PGetCurrentProcessId pGetCurrentProcessId;
PGetCurrentThreadId pGetCurrentThreadId;
PBuildCommDCB pBuildCommDCB;

bool load_winapi() {
    HANDLE hKernel32, hUser32;

    pLoadLibraryW = get_func_from_peb(L"kernel32.dll", "LoadLibraryW");
    pGetProcAddress = get_func_from_peb(L"kernel32.dll", "GetProcAddress");
    if(!pLoadLibraryW || !pGetProcAddress) {
        // Failed to find initial functions
        return false;
    }

    hKernel32 = LoadLibraryW(L"kernel32.dll");
    hUser32 = LoadLibraryW(L"user32.dll");

    pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    pExpandEnvironmentStringsW = GetProcAddress(hKernel32, "ExpandEnvironmentStringsW");
    pOutputDebugStringW = GetProcAddress(hKernel32, "OutputDebugStringW");
    pCloseHandle = GetProcAddress(hKernel32, "CloseHandle");
    pCreateFileW = GetProcAddress(hKernel32, "CreateFileW");
    pReadFile = GetProcAddress(hKernel32, "ReadFile");
    pWriteFile = GetProcAddress(hKernel32, "WriteFile");
    pCreateProcessW = GetProcAddress(hKernel32, "CreateProcessW");
    pExitThread = GetProcAddress(hKernel32, "ExitThread");
    pSleep = GetProcAddress(hKernel32, "Sleep");
    pVirtualFree = GetProcAddress(hKernel32, "VirtualFree");
    pGetLastError = GetProcAddress(hKernel32, "GetLastError");
    pGetCommState = GetProcAddress(hKernel32, "GetCommState");
    pSetCommState = GetProcAddress(hKernel32, "SetCommState");
    pCreatePipe = GetProcAddress(hKernel32, "CreatePipe");
    pSetHandleInformation = GetProcAddress(hKernel32, "SetHandleInformation");
    pWaitForMultipleObjects = GetProcAddress(hKernel32, "WaitForMultipleObjects");
    pCreateEvent = GetProcAddress(hKernel32, "CreateEventA");
    pGetOverlappedResult = GetProcAddress(hKernel32, "GetOverlappedResult");
    pCancelIo = GetProcAddress(hKernel32, "CancelIo");
    pGetExitCodeProcess = GetProcAddress(hKernel32, "GetExitCodeProcess");
    pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
    pCreateNamedPipeW = GetProcAddress(hKernel32, "CreateNamedPipeW");
    pWaitForSingleObject = GetProcAddress(hKernel32, "WaitForSingleObject");
    pSetLastError = GetProcAddress(hKernel32, "SetLastError");
    pGetCurrentProcessId = GetProcAddress(hKernel32, "GetCurrentProcessId");
    pGetCurrentThreadId = GetProcAddress(hKernel32, "GetCurrentThreadId");
    pBuildCommDCB = GetProcAddress(hKernel32, "BuildCommDCBA");

    return true;
}
