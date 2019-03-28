#pragma once
#pragma pack(push,1)
#pragma warning( disable : 4200 )

#define  STATUS_SUCCESS                 0x00000000
#define  STATUS_ACCESS_DENIED           0xC0000022
#define  STATUS_INFO_LENGTH_MISMATCH    0xC0000004
#define  STATUS_NO_SUCH_FILE            0xC000000F
#define  STATUS_NO_MORE_ENTRIES         0x8000001A
#define  STATUS_BUFFER_TOO_SMALL        0xC0000023


#define OB_TYPE_FILE_XP    28
#define OB_TYPE_FILE_2000  26

//typedef DWORD NTSTATUS;
typedef VOID NTSYSAPI (*PPEBLOCKROUTINE)(pvoid_t);


#define THREAD_BASIC_INFO  0x0

typedef enum _SECTION_INHERIT {
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;


typedef enum _SYSTEM_INFORMATION_CLASS 
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation, 
    SystemNotImplemented1,
    SystemProcessesAndThreadsInformation,
    SystemCallCounts, 
    SystemConfigurationInformation, 
    SystemProcessorTimes, 
    SystemGlobalFlag, 
    SystemNotImplemented2, 
    SystemModuleInformation, 
    SystemLockInformation,
    SystemNotImplemented3, 
    SystemNotImplemented4, 
    SystemNotImplemented5, 
    SystemHandleInformation, 
    SystemObjectInformation, 
    SystemPagefileInformation, 
    SystemInstructionEmulationCounts, 
    SystemInvalidInfoClass1, 
    SystemCacheInformation, 
    SystemPoolTagInformation, 
    SystemProcessorStatistics,
    SystemDpcInformation, 
    SystemNotImplemented6,
    SystemLoadImage, 
    SystemUnloadImage, 
    SystemTimeAdjustment, 
    SystemNotImplemented7, 
    SystemNotImplemented8, 
    SystemNotImplemented9,
    SystemCrashDumpInformation, 
    SystemExceptionInformation, 
    SystemCrashDumpStateInformation, 
    SystemKernelDebuggerInformation, 
    SystemContextSwitchInformation, 
    SystemRegistryQuotaInformation, 
    SystemLoadAndCallImage,
    SystemPrioritySeparation, 
    SystemNotImplemented10,
    SystemNotImplemented11, 
    SystemInvalidInfoClass2, 
    SystemInvalidInfoClass3, 
    SystemTimeZoneInformation, 
    SystemLookasideInformation, 
    SystemSetTimeSlipEvent,
    SystemCreateSession,
    SystemDeleteSession, 
    SystemInvalidInfoClass4, 
    SystemRangeStartInformation, 
    SystemVerifierInformation, 
    SystemAddVerifier, 
    SystemSessionProcessesInformation 
} SYSTEM_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS 
{
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileModeInformation = 16,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation
} FILE_INFORMATION_CLASS;


typedef enum KEY_INFORMATION_CLASS 
{
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation
} KEY_INFORMATION_CLASS;

typedef enum KEY_VALUE_INFORMATION_CLASS 
{
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation 
} KEY_VALUE_INFORMATION_CLASS;

typedef struct KEY_VALUE_BASIC_INFORMATION 
{
    ULONG  TitleIndex;
    ULONG  Type;
    ULONG  NameLength;
    wchar_t  Name[1];  //  Variable size
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct KEY_BASIC_INFORMATION 
{
    LARGE_INTEGER LastWriteTime;
    ULONG  TitleIndex;
    ULONG  NameLength;
    wchar_t  Name[1];  //  Variable-length string
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;


typedef struct  KEY_VALUE_PARTIAL_INFORMATION 
{
    ULONG   TitleIndex;
    ULONG   Typy;
    ULONG   DataLength;	
    UCHAR   Data [1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct KEY_FULL_INFORMATION 
{
    LARGE_INTEGER  LastWriteTime;
    ULONG  TitleIndex;
    ULONG  ClassOffset;
    ULONG  ClassLength;
    ULONG  SubKeys;
    ULONG  MaxNameLen;
    ULONG  MaxClassLen;
    ULONG  Values;
    ULONG  MaxValueNameLen;
    ULONG  MaxValueDataLen;
    wchar_t  Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct KEY_NODE_INFORMATION 
{
    LARGE_INTEGER LastWriteTime;
    ULONG  TitleIndex;
    ULONG  ClassOffset;
    ULONG  ClassLength;
    ULONG  NameLength;
    wchar_t  Name[1];  //  Variable-length string
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct SYSTEM_MODULE_INFORMATION 
{
    ULONG Reserved[2];
    pvoid_t Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct SYSTEM_MODULE_INFORMATION_EX
{
    ULONG ModulesCount;
    SYSTEM_MODULE_INFORMATION Modules[0];
} SYSTEM_MODULE_INFORMATION_EX, *PSYSTEM_MODULE_INFORMATION_EX;

typedef struct SYSTEM_HANDLE_INFORMATION 
{
    DWORD ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    WORD Handle;
    pvoid_t pObject;
    DWORD GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct SYSTEM_HANDLE_INFORMATION_EX
{
    DWORD NumberOfHandles;
    SYSTEM_HANDLE_INFORMATION Information[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;


typedef struct IO_STATUS_BLOCK 
{ 
    DWORD Status;
    DWORD Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK ;

typedef struct _FILE_NAME_INFORMATION {
    ULONG  FileNameLength;
    wchar_t  FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;


typedef struct _PROCESS_BASIC_INFORMATION
{
    BOOL ExitStatus;
    pvoid_t PebBaseAddress;
    PULONG AffinityMask;
    DWORD BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

#define ProcessBasicInformation 0


typedef struct  UnicodeString 
{
    WORD Length;
    WORD MaximumLength;
    PWCHAR Buffer;
} UnicodeString, *PUnicodeString;


typedef struct CLIENT_ID 
{
    DWORD UniqueProcess;
    DWORD UniqueThread;
} CLIENT_ID , *PCLIENT_ID;


typedef struct VM_COUNTERS 
{
    DWORD PeakVirtualSize;
    DWORD VirtualSize;
    DWORD PageFaultCount;
    DWORD PeakWorkingSetSize;
    DWORD WorkingSetSize;
    DWORD QuotaPeakPagedPoolUsage;
    DWORD QuotaPagedPoolUsage;
    DWORD QuotaPeakNonPagedPoolUsage;
    DWORD QuotaNonPagedPoolUsage;
    DWORD PagefileUsage;
    DWORD PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;



typedef struct SYSTEM_THREADS
{
    LARGE_INTEGER KernelTime,
        UserTime,
        CreateTime;
    DWORD WaitTime;
    pvoid_t StartAddress;
    CLIENT_ID ClientId;
    DWORD Priority,
        BasePriority,
        ContextSwitchCount;
    DWORD State;
    DWORD WaitReason;
} SYSTEM_THREADS,  *PSYSTEM_THREADS;



typedef struct SYSTEM_PROCESSES 
{
    DWORD NextEntryDelta;
    DWORD ThreadCount;
    DWORD Reserved1[6]; 
    LARGE_INTEGER CreateTime; 
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UnicodeString ProcessName;
    DWORD BasePriority;
    DWORD ProcessId;
    DWORD InheritedFromProcessId;
    DWORD HandleCount;
    DWORD Reserved2[2]; 
    VM_COUNTERS VmCounters;
    IO_COUNTERS IoCounters; // Windows 2000 only
    SYSTEM_THREADS Threads[];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;



#define FileDirectoryInformation 1 
#define FileFullDirectoryInformation 2
#define FileBothDirectoryInformation 3
#define FileNamesInformation  12


//for FileDirectoryInformation: 

typedef struct FILE_DIRECTORY_INFORMATION 
{
    ULONG NextEntryOffset;
    ULONG Unknown; 
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;  
    ULONG FileAttributes; 
    ULONG FileNameLength; 
    wchar_t FileName[1];  
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;


//for FileFullDirectoryInformation:

typedef struct FILE_FULL_DIRECTORY_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG Unknown; 
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize; 
    ULONG FileAttributes; 
    ULONG FileNameLength;
    ULONG EaInformationLength;
    wchar_t FileName[1]; 
} FILE_FULL_DIRECTORY_INFORMATION, *PFILE_FULL_DIRECTORY_INFORMATION;


//for FileBothDirectoryInformation:

typedef struct FILE_BOTH_DIRECTORY_INFORMATION  
{
    ULONG NextEntryOffset;
    ULONG Unknown;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG  FileAttributes;
    ULONG  FileNameLength;
    ULONG  EaInformationLength;
    USHORT AlternateNameLength;
    wchar_t  AlternateName[12];
    wchar_t  FileName[1];
} FILE_BOTH_DIRECTORY_INFORMATION, *PFILE_BOTH_DIRECTORY_INFORMATION;


//for FileNamesInformation:

typedef struct FILE_NAMES_INFORMATION 
{
    ULONG NextEntryOffset; 
    ULONG Unknown;
    ULONG FileNameLength;
    wchar_t FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;



typedef struct THREAD_BASIC_INFORMATION 
{
    NTSTATUS ExitStatus;
    PNT_TIB TebBaseAddress;
    CLIENT_ID ClientId;
    DWORD AffinityMask;
    DWORD Priority;
    DWORD BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;


typedef struct ANSII_CHAR
{
    ULONG Length;
    ULONG MaximumLength;
    PCHAR Buffer;
} ANSII_CHAR, *PANSII_CHAR ;

typedef struct LDR_DATA_TABLE_ENTRY 
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    pvoid_t DllBase;
    pvoid_t EntryPoint;
    ULONG SizeOfImage;
    UnicodeString FullDllName;
    UnicodeString BaseDllName;
    ULONG Flags;
    ULONG LoadCount;
    ULONG TlsIndex;
    LIST_ENTRY HashLinks;
    pvoid_t SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    pvoid_t LoadedImports;
    pvoid_t EntryPointActivationContext;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct PEB_LDR_DATA
{
    ULONG      Length;
    ULONG      Initialized;
    pvoid_t      SsHandle;
    LIST_ENTRY InLoadOrderModuleList; 
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    pvoid_t      EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct RTL_DRIVE_LETTER_CURDIR
{
    USHORT      Flags;
    USHORT      Length;
    ULONG       TimeStamp;
    ANSII_CHAR    DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;


typedef struct RTL_USER_PROCESS_PARAMETERS 
{ 
    ULONG                   MaximumLength; 
    ULONG                   Length; 
    ULONG                   Flags; 
    ULONG                   DebugFlags; 
    pvoid_t                   ConsoleHandle; 
    ULONG                   ConsoleFlags; 
    HANDLE                  StdInputHandle; 
    HANDLE                  StdOutputHandle; 
    HANDLE                  StdErrorHandle; 
    UnicodeString           CurrentDirectoryPath; 
    HANDLE                  CurrentDirectoryHandle; 
    UnicodeString           DllPath; 
    UnicodeString           ImagePathName; 
    UnicodeString           CommandLine; 
    pvoid_t                   Environment; 
    ULONG                   StartingPositionLeft; 
    ULONG                   StartingPositionTop; 
    ULONG                   Width; 
    ULONG                   Height; 
    ULONG                   CharWidth; 
    ULONG                   CharHeight; 
    ULONG                   ConsoleTextAttributes; 
    ULONG                   WindowFlags; 
    ULONG                   ShowWindowFlags; 
    UnicodeString          WindowTitle; 
    UnicodeString          DesktopName; 
    UnicodeString          ShellInfo; 
    UnicodeString          RuntimeData; 
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20]; 
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK *Next;
    ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;


typedef struct PEB 
{ 
    UCHAR                   InheritedAddressSpace; 
    UCHAR                   ReadImageFileExecOptions; 
    UCHAR                   BeingDebugged; 
    UCHAR                   Spare; 
    HANDLE                  Mutant; 
    pvoid_t                   ImageBaseAddress; 
    PPEB_LDR_DATA           LoaderData; 
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters; 
    pvoid_t                   SubSystemData; 
    pvoid_t                   ProcessHeap; 
    pvoid_t                   FastPebLock; 
    PPEBLOCKROUTINE         FastPebLockRoutine; 
    PPEBLOCKROUTINE         FastPebUnlockRoutine; 
    ULONG                   EnvironmentUpdateCount; 
    pvoid_t                   KernelCallbackTable;
    ULONG                   SystemReserved[1];
    ULONG                   AtlThunkSListPtr32;
    PPEB_FREE_BLOCK         FreeList;
    ULONG                   TlsExpansionCounter;
    pvoid_t                   TlsBitmap;
    ULONG                   TlsBitmapBits[2];
    pvoid_t                   ReadOnlySharedMemoryBase;
    pvoid_t                   ReadOnlySharedMemoryHeap; 
    pvoid_t *                 ReadOnlyStaticServerData; 
    pvoid_t                   AnsiCodePageData; 
    pvoid_t                   OemCodePageData; 
    pvoid_t                   UnicodeCaseTableData; 
    ULONG                   NumberOfProcessors; 
    ULONG                   NtGlobalFlag;
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve; 
    ULONG                   HeapSegmentCommit; 
    ULONG                   HeapDeCommitTotalFreeThreshold; 
    ULONG                   HeapDeCommitFreeBlockThreshold; 
    ULONG                   NumberOfHeaps; 
    ULONG                   MaximumNumberOfHeaps; 
    pvoid_t                   *ProcessHeaps; 
    pvoid_t                   GdiSharedHandleTable; 
    pvoid_t                   ProcessStarterHelper; 
    pvoid_t                   GdiDCAttributeList; 
    pvoid_t                   LoaderLock; 
    ULONG                   OSMajorVersion; 
    ULONG                   OSMinorVersion; 
    ULONG                   OSBuildNumber; 
    ULONG                   OSPlatformId; 
    ULONG                   ImageSubSystem; 
    ULONG                   ImageSubSystemMajorVersion; 
    ULONG                   ImageSubSystemMinorVersion; 
    ULONG                   GdiHandleBuffer[34]; 
    pvoid_t                   PostProcessInitRoutine; 
    pvoid_t                   TlsExpansionBitmap; 
    UCHAR                   TlsExpansionBitmapBits[32];
    ULONG                   SessionId;
    LARGE_INTEGER           AppCompatFlags;
    LARGE_INTEGER           AppCompatFlagsUser;
    pvoid_t                   pShimData;
    pvoid_t                   AppCompatInfo;
    UnicodeString           CSDVersion;
    pvoid_t                   ActivationContextData;
    pvoid_t                   ProcessAssemblyStorageMap;
    pvoid_t                   SystemDefaultActivationContextData;
    pvoid_t                   SystemAssemblyStorageMap;
    ULONG                   MinimumStackCommit;
} PEB, *PPEB;



NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
                         IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                         IN OUT pvoid_t SystemInformation,
                         IN ULONG SystemInformationLength,
                         OUT PULONG ReturnLength OPTIONAL);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationFile(
                       IN HANDLE FileHandle, 
                       OUT PIO_STATUS_BLOCK IoStatusBlock,
                       OUT pvoid_t FileInformation, 
                       IN ULONG FileInformationLength,
                       OUT FILE_INFORMATION_CLASS FileInformationClass);



NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(IN HANDLE ProcessHandle,
                          IN DWORD ProcessInformationClass,
                          OUT pvoid_t ProcessInformation,
                          IN ULONG ProcessInformationLength,
                          OUT PULONG ReturnLength);


NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryFile(IN HANDLE FileHandle,
                     IN DWORD Event,
                     IN pvoid_t ApcRoutine,
                     IN pvoid_t ApcContext,
                     OUT pvoid_t IoStatusBlock,
                     OUT pvoid_t FileInformation,
                     IN DWORD FileInformationLength,
                     IN DWORD FileInformationClass,
                     IN BOOL  ReturnSingleEntry,
                     IN PUnicodeString FileName,
                     IN BOOL RestartScan);



NTSYSAPI
NTSTATUS
NTAPI
ZwCreateThread(OUT PHANDLE ThreadHandle,
               IN ACCESS_MASK DesiredAccess,
               IN pvoid_t ObjectAttributes,
               IN HANDLE ProcessHandle,
               OUT PCLIENT_ID ClientId,
               IN PCONTEXT ThreadContext,
               IN pvoid_t UserStack,
               IN BOOLEAN CreateSuspended);


NTSYSAPI
NTSTATUS
NTAPI
ZwResumeThread(IN HANDLE ThreadHandle,
               OUT PULONG PreviousSuspendCount OPTIONAL);



NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(IN HANDLE ThreadHandle,
                         IN DWORD ThreadInformationClass,
                         OUT pvoid_t ThreadInformation,
                         IN ULONG ThreadInformationLength,
                         OUT PULONG ReturnLength OPTIONAL);



NTSYSAPI
NTSTATUS
NTAPI
ZwEnumerateKey(IN HANDLE  KeyHandle,
               IN ULONG  Index,
               IN DWORD  KeyInformationClass,
               OUT pvoid_t  KeyInformation,
               IN ULONG  Length,
               OUT PULONG  ResultLength );


NTSYSAPI
NTSTATUS
NTAPI
ZwEnumerateValueKey(IN HANDLE KeyHandle,
                    IN ULONG Index,
                    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                    OUT pvoid_t KeyValueInformation,
                    IN ULONG KeyValueInformationLength,
                    OUT PULONG ResultLength);



NTSYSAPI
NTSTATUS
NTAPI
ZwTerminateProcess(IN HANDLE hProcess,
                   IN ULONG ExitCode);



NTSYSAPI
NTSTATUS
NTAPI
DbgUiDebugActiveProcess(IN HANDLE Handle);



NTSYSAPI
NTSTATUS
NTAPI
DbgUiConnectToDbg(); 


NTSYSAPI 
NTSTATUS
NTAPI
NtAllocateVirtualMemory(IN HANDLE  ProcessHandle, 
                        IN OUT pvoid_t *BaseAddress,
                        IN ULONG ZeroBits,
                        IN OUT PULONG RegionSize,
                        IN ULONG AllocationType,
                        IN ULONG Protect);


NTSYSAPI 
NTSTATUS
NTAPI
NtWriteVirtualMemory(IN HANDLE               ProcessHandle,
                     IN pvoid_t                BaseAddress,
                     IN pvoid_t                Buffer,
                     IN ULONG                NumberOfBytesToWrite,
                     OUT PULONG              NumberOfBytesWritten OPTIONAL );


WINBASEAPI
BOOL
WINAPI
CreateTimerQueueTimer(
                      PHANDLE phNewTimer,
                      HANDLE TimerQueue,
                      WAITORTIMERCALLBACKFUNC Callback,
                      pvoid_t Parameter,
                      DWORD DueTime,
                      DWORD Period,
                      ULONG Flags
                      ) ;



NTSYSAPI 
NTSTATUS
NTAPI
NtAdjustPrivilegesToken(IN HANDLE               TokenHandle,
                        IN BOOLEAN              DisableAllPrivileges,
                        IN PTOKEN_PRIVILEGES    TokenPrivileges,
                        IN ULONG                PreviousPrivilegesLength,
                        OUT PTOKEN_PRIVILEGES   PreviousPrivileges OPTIONAL,
                        OUT PULONG              RequiredLength OPTIONAL );



//
// Valid values for the Attributes field
//

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_VALID_ATTRIBUTES    0x000003F2L

//
// Object Attributes structure
//

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUnicodeString ObjectName;
    ULONG Attributes;
    pvoid_t SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    pvoid_t SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;



//++
//
// VOID
// InitializeObjectAttributes(
//     OUT POBJECT_ATTRIBUTES p,
//     IN PUNICODE_STRING n,
//     IN ULONG a,
//     IN HANDLE r,
//     IN PSECURITY_DESCRIPTOR s
//     )
//
//--

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}


//
// Define the create/open option flags
//


NTSYSAPI
NTSTATUS
NTAPI
ZwOpenKey(OUT PHANDLE KeyHandle,
          IN ACCESS_MASK DesiredAccess,
          IN POBJECT_ATTRIBUTES ObjectAttributes);


NTSYSAPI
NTSTATUS
NTAPI
ZwSetValueKey(IN HANDLE                KeyHandle,
              IN PUnicodeString        ValueName,
              IN ULONG                TitleIndex,
              IN ULONG                Type,
              IN pvoid_t                Data,
              IN ULONG                DataSize );


NTSYSAPI 
NTSTATUS
NTAPI
ZwDeleteKey(IN HANDLE KeyHandle);


NTSYSAPI 
NTSTATUS
NTAPI
ZwCreateKey(OUT PHANDLE             pKeyHandle,
            IN ACCESS_MASK          DesiredAccess,
            IN POBJECT_ATTRIBUTES   ObjectAttributes,
            IN ULONG                TitleIndex,
            IN PUnicodeString       Class OPTIONAL,
            IN ULONG                CreateOptions,
            OUT PULONG              Disposition OPTIONAL );


NTSYSAPI 
NTSTATUS
NTAPI
ZwQueryValueKey(IN HANDLE               KeyHandle,
                IN PUnicodeString       ValueName,
                IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                OUT pvoid_t               KeyValueInformation,
                IN ULONG                Length,
                OUT PULONG              ResultLength );



NTSYSAPI 
NTSTATUS
NTAPI
ZwClose(IN HANDLE   ObjectHandle);



#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005




NTSYSAPI 
NTSTATUS
NTAPI
ZwCreateFile(OUT PHANDLE             FileHandle,
             IN ACCESS_MASK          DesiredAccess,
             IN POBJECT_ATTRIBUTES   ObjectAttributes,
             OUT PIO_STATUS_BLOCK    IoStatusBlock,
             IN PLARGE_INTEGER       AllocationSize OPTIONAL,
             IN ULONG                FileAttributes,
             IN ULONG                ShareAccess,
             IN ULONG                CreateDisposition,
             IN ULONG                CreateOptions,
             IN pvoid_t                EaBuffer OPTIONAL,
             IN ULONG                EaLength );



NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(PUnicodeString DestinationString,
                     PCWSTR SourceString);



typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
                          IN pvoid_t ApcContext,
                          IN PIO_STATUS_BLOCK IoStatusBlock,
                          IN ULONG Reserved
                          );
#define PIO_APC_ROUTINE_DEFINED



NTSYSAPI 
NTSTATUS
NTAPI
ZwWriteFile(IN HANDLE                FileHandle,
            IN HANDLE               Event OPTIONAL,
            IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
            IN pvoid_t                ApcContext OPTIONAL,
            OUT PIO_STATUS_BLOCK    IoStatusBlock,
            IN pvoid_t                Buffer,
            IN ULONG                Length,
            IN PLARGE_INTEGER       ByteOffset OPTIONAL,
            IN PULONG               Key OPTIONAL );


typedef struct _USER_STACK 
{
    pvoid_t                FixedStackBase;
    pvoid_t                FixedStackLimit;
    pvoid_t                ExpandableStackBase;
    pvoid_t                ExpandableStackLimit;
    pvoid_t                ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;



NTSYSAPI 
NTSTATUS
NTAPI
ZwProtectVirtualMemory(IN HANDLE               ProcessHandle,
                       IN OUT pvoid_t            *BaseAddress,
                       IN OUT PULONG           NumberOfBytesToProtect,
                       IN ULONG                NewAccessProtection,
                       OUT PULONG              OldAccessProtection );




typedef struct _SECTION_IMAGE_INFORMATION 
{
    pvoid_t                   EntryPoint;
    ULONG                   StackZeroBits;
    ULONG                   StackReserved;
    ULONG                   StackCommit;
    ULONG                   ImageSubsystem;
    WORD                    SubsystemVersionLow;
    WORD                    SubsystemVersionHigh;
    ULONG                   Unknown1;
    ULONG                   ImageCharacteristics;
    ULONG                   ImageMachineType;
    ULONG                   Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;


typedef struct CSRSS_MESSAGE
{
    DWORD Unknown1;
    DWORD Opcode;
    DWORD Status;
    DWORD Unknown2;
} CSRSS_MESSAGE , *PCSRSS_MESSAGE;

typedef struct PORT_MESSAGE
{
    //    USHORT DataSize;
    USHORT MessageSize;
    USHORT MessageType;
    USHORT VirtualRangesOffset;
    CLIENT_ID ClientId;
    ULONG  MessageId;
    ULONG SectionSize;
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct CSRSSMSG
{
    PORT_MESSAGE PortMessage;
    CSRSS_MESSAGE CsrssMessage;
    PROCESS_INFORMATION ProcessInformation;
    CLIENT_ID Debugger;
    ULONG CreationFlag;
    ULONG VdmInfo[2];
} CSRSSMSG , *PCSRSSMSG;


NTSYSAPI 
NTSTATUS
NTAPI CsrClientCallServer(IN pvoid_t Message,
                          IN pvoid_t,
                          IN ULONG Opcode,
                          IN ULONG Size);

typedef struct _LPC_SECTION_MEMORY 
{
    ULONG                   Length;
    ULONG                   ViewSize;
    pvoid_t                   ViewBase;
} LPC_SECTION_MEMORY, *PLPC_SECTION_MEMORY;


typedef struct _LPC_SECTION_OWNER_MEMORY 
{
    ULONG                   Length;
    HANDLE                  SectionHandle;
    ULONG                   OffsetInSection;
    ULONG                   ViewSize;
    pvoid_t                   ViewBase;
    pvoid_t                   OtherSideViewBase;
} LPC_SECTION_OWNER_MEMORY, *PLPC_SECTION_OWNER_MEMORY;



NTSYSAPI 
NTSTATUS
NTAPI
ZwConnectPort(OUT PHANDLE             ClientPortHandle,
              IN PUnicodeString      ServerPortName,
              IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
              IN OUT PLPC_SECTION_OWNER_MEMORY ClientSharedMemory OPTIONAL,
              OUT PLPC_SECTION_MEMORY ServerSharedMemory OPTIONAL,
              OUT PULONG              MaximumMessageLength OPTIONAL,
              IN OUT pvoid_t            ConnectionInfo OPTIONAL,
              IN OUT PULONG           ConnectionInfoLength OPTIONAL );


typedef struct _LPC_MESSAGE 
{
    USHORT                  DataLength;
    USHORT                  Length;
    USHORT                  MessageType;
    USHORT                  DataInfoOffset;
    CLIENT_ID               ClientId;
    ULONG                   MessageId;
    ULONG                   CallbackId;
} LPC_MESSAGE, *PLPC_MESSAGE;



NTSYSAPI 
NTSTATUS
NTAPI
ZwRequestWaitReplyPort(IN HANDLE               PortHandle,
                       IN PLPC_MESSAGE         Request,
                       OUT PLPC_MESSAGE        IncomingReply );


DWORD
GetMnemonicLen();



NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteFile(IN POBJECT_ATTRIBUTES ObjectAttributes);


NTSYSAPI
NTSTATUS
NTAPI
ZwFlushKey(IN HANDLE KeyHandle);

#pragma warning( default : 4200 )