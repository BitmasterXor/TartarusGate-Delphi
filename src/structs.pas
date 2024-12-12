unit structs;

{$ALIGN 8}
{$MINENUMSIZE 4}

interface

uses
  Windows,SysUtils;

type
  _LSA_UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: PWIDECHAR;
  end;
  LSA_UNICODE_STRING = _LSA_UNICODE_STRING;
  PLSA_UNICODE_STRING = ^LSA_UNICODE_STRING;
  UNICODE_STRING = LSA_UNICODE_STRING;
  PUNICODE_STRING = ^UNICODE_STRING;
  PUNICODE_STR = PUNICODE_STRING;


type
  _LDR_MODULE = record
    InLoadOrderModuleList: LIST_ENTRY;
    InMemoryOrderModuleList: LIST_ENTRY;
    InInitializationOrderModuleList: LIST_ENTRY;
    BaseAddress: PVOID;
    EntryPoint: PVOID;
    SizeOfImage: ULONG;
    FullDllName: UNICODE_STRING;
    BaseDllName: UNICODE_STRING;
    Flags: ULONG;
    LoadCount: SHORT;
    TlsIndex: SHORT;
    HashTableEntry: LIST_ENTRY;
    TimeDateStamp: ULONG;
  end;
  LDR_MODULE = _LDR_MODULE;
  PLDR_MODULE = ^LDR_MODULE;


type
  _PEB_LDR_DATA = record
    Length: ULONG;
    Initialized: ULONG;
    SsHandle: PVOID;
    InLoadOrderModuleList: LIST_ENTRY;
    InMemoryOrderModuleList: LIST_ENTRY;
    InInitializationOrderModuleList: LIST_ENTRY;
  end;
  PEB_LDR_DATA = _PEB_LDR_DATA;
  PPEB_LDR_DATA = ^PEB_LDR_DATA;

type
  _PEB = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    Spare: BOOLEAN;
    Mutant: THandle;
    ImageBase: PVOID;
    LoaderData: PPEB_LDR_DATA;
    ProcessParameters: PVOID;
    SubSystemData: PVOID;
    ProcessHeap: PVOID;
    FastPebLock: PVOID;
    FastPebLockRoutine: PVOID;
    FastPebUnlockRoutine: PVOID;
    EnvironmentUpdateCount: ULONG;
    KernelCallbackTable: ^PVOID;
    EventLogSection: PVOID;
    EventLog: PVOID;
    FreeList: PVOID;
    TlsExpansionCounter: ULONG;
    TlsBitmap: PVOID;
    TlsBitmapBits: array[0..1] of ULONG;
    ReadOnlySharedMemoryBase: PVOID;
    ReadOnlySharedMemoryHeap: PVOID;
    ReadOnlyStaticServerData: ^PVOID;
    AnsiCodePageData: PVOID;
    OemCodePageData: PVOID;
    UnicodeCaseTableData: PVOID;
    NumberOfProcessors: ULONG;
    NtGlobalFlag: ULONG;
    Spare2: array[0..3] of BYTE;
    CriticalSectionTimeout: LARGE_INTEGER;
    HeapSegmentReserve: ULONG;
    HeapSegmentCommit: ULONG;
    HeapDeCommitTotalFreeThreshold: ULONG;
    HeapDeCommitFreeBlockThreshold: ULONG;
    NumberOfHeaps: ULONG;
    MaximumNumberOfHeaps: ULONG;
    ProcessHeaps: ^PPVOID;
    GdiSharedHandleTable: PVOID;
    ProcessStarterHelper: PVOID;
    GdiDCAttributeList: PVOID;
    LoaderLock: PVOID;
    OSMajorVersion: ULONG;
    OSMinorVersion: ULONG;
    OSBuildNumber: ULONG;
    OSPlatformId: ULONG;
    ImageSubSystem: ULONG;
    ImageSubSystemMajorVersion: ULONG;
    ImageSubSystemMinorVersion: ULONG;
    GdiHandleBuffer: array[0..33] of ULONG;
    PostProcessInitRoutine: ULONG;
    TlsExpansionBitmap: ULONG;
    TlsExpansionBitmapBits: array[0..127] of BYTE;
    SessionId: ULONG;
  end;
  PEB = _PEB;
  PPEB = ^PEB;

type
  // CLIENT_ID structure
  __CLIENT_ID = record
    UniqueProcess: THandle;
    UniqueThread: THandle;
  end;
  CLIENT_ID = __CLIENT_ID;
  PCLIENT_ID = ^CLIENT_ID;

  // TEB_ACTIVE_FRAME_CONTEXT structure
  _TEB_ACTIVE_FRAME_CONTEXT = record
    Flags: ULONG;
    FrameName: PAnsiChar;  // PCHAR becomes PAnsiChar in Delphi
  end;
  TEB_ACTIVE_FRAME_CONTEXT = _TEB_ACTIVE_FRAME_CONTEXT;
  PTEB_ACTIVE_FRAME_CONTEXT = ^TEB_ACTIVE_FRAME_CONTEXT;

  // Forward declaration for _TEB_ACTIVE_FRAME
  PTEB_ACTIVE_FRAME = ^TEB_ACTIVE_FRAME;

  // TEB_ACTIVE_FRAME structure
  _TEB_ACTIVE_FRAME = record
    Flags: ULONG;
    Previous: PTEB_ACTIVE_FRAME;
    Context: PTEB_ACTIVE_FRAME_CONTEXT;
  end;
  TEB_ACTIVE_FRAME = _TEB_ACTIVE_FRAME;

  // GDI_TEB_BATCH structure
  _GDI_TEB_BATCH = record
    Offset: ULONG;
    HDC: ULONG;
    Buffer: array[0..309] of ULONG;  // 310 elements in Delphi style
  end;
  GDI_TEB_BATCH = _GDI_TEB_BATCH;
  PGDI_TEB_BATCH = ^GDI_TEB_BATCH;

  // ACTIVATION_CONTEXT type
  PACTIVATION_CONTEXT = PVOID;

  // Forward declaration for RTL_ACTIVATION_CONTEXT_STACK_FRAME
  PRTL_ACTIVATION_CONTEXT_STACK_FRAME = ^RTL_ACTIVATION_CONTEXT_STACK_FRAME;

  // RTL_ACTIVATION_CONTEXT_STACK_FRAME structure
  _RTL_ACTIVATION_CONTEXT_STACK_FRAME = record
    Previous: PRTL_ACTIVATION_CONTEXT_STACK_FRAME;
    ActivationContext: PACTIVATION_CONTEXT;
    Flags: ULONG;
  end;
  RTL_ACTIVATION_CONTEXT_STACK_FRAME = _RTL_ACTIVATION_CONTEXT_STACK_FRAME;

  // ACTIVATION_CONTEXT_STACK structure
  _ACTIVATION_CONTEXT_STACK = record
    ActiveFrame: PRTL_ACTIVATION_CONTEXT_STACK_FRAME;
    FrameListCache: LIST_ENTRY;
    Flags: ULONG;
    NextCookieSequenceNumber: ULONG;
    StackId: ULONG;
  end;
  ACTIVATION_CONTEXT_STACK = _ACTIVATION_CONTEXT_STACK;
  PACTIVATION_CONTEXT_STACK = ^ACTIVATION_CONTEXT_STACK;


type
  PEXCEPTION_REGISTRATION_RECORD = ^EXCEPTION_REGISTRATION_RECORD;
  _EXCEPTION_REGISTRATION_RECORD = record
    Next: PEXCEPTION_REGISTRATION_RECORD;
    Handler: PVOID;
  end;
  EXCEPTION_REGISTRATION_RECORD = _EXCEPTION_REGISTRATION_RECORD;

type
  PNT_TIB = ^NT_TIB;
  _NT_TIB = record
    ExceptionList: PEXCEPTION_REGISTRATION_RECORD;
    StackBase: PVOID;
    StackLimit: PVOID;
    SubSystemTib: PVOID;
    case Integer of
      0: (
        FiberData: PVOID;
        ArbitraryUserPointer: PVOID;
        Self: PNT_TIB;
      );
      1: (
        Version: DWORD;
        ArbitraryUserPointer2: PVOID;
        Self2: PNT_TIB;
      );
  end;
  NT_TIB = _NT_TIB;

type
  Wx86ThreadState = record
    CallBx86Eip: PULONG;
    DeallocationCpu: PVOID;
    UseKnownWx86Dll: BOOLEAN;
    OleStubInvoked: BOOLEAN;
  end;

type
  _TEB = record
    NtTib: NT_TIB;
    EnvironmentPointer: PVOID;
    ClientId: CLIENT_ID;
    ActiveRpcHandle: PVOID;
    ThreadLocalStoragePointer: PVOID;
    ProcessEnvironmentBlock: PPEB;
    LastErrorValue: ULONG;
    CountOfOwnedCriticalSections: ULONG;
    CsrClientThread: PVOID;
    Win32ThreadInfo: PVOID;
    User32Reserved: array[0..25] of ULONG;
    UserReserved: array[0..4] of ULONG;
    WOW32Reserved: PVOID;
    CurrentLocale: LCID;
    FpSoftwareStatusRegister: ULONG;
    SystemReserved1: array[0..53] of PVOID;
    ExceptionCode: LONG;

    // Note: We'll use WINVER to determine which variant to use
    {$IFDEF WINVER >= $0600} // NTDDI_LONGHORN
    ActivationContextStackPointer: ^PACTIVATION_CONTEXT_STACK;
    SpareBytes1: array[0..($30 - 3 * SizeOf(PVOID) - 1)] of BYTE;
    TxFsContext: ULONG;
    {$ELSE}
      {$IFDEF WINVER >= $0502} // NTDDI_WS03
      ActivationContextStackPointer: PACTIVATION_CONTEXT_STACK;
      SpareBytes1: array[0..($34 - 3 * SizeOf(PVOID) - 1)] of BYTE;
      {$ELSE}
      ActivationContextStack: ACTIVATION_CONTEXT_STACK;
      SpareBytes1: array[0..23] of BYTE;
      {$ENDIF}
    {$ENDIF}

    GdiTebBatch: GDI_TEB_BATCH;
    RealClientId: CLIENT_ID;
    GdiCachedProcessHandle: PVOID;
    GdiClientPID: ULONG;
    GdiClientTID: ULONG;
    GdiThreadLocalInfo: PVOID;
    Win32ClientInfo: array[0..61] of PSIZE_T;
    glDispatchTable: array[0..232] of PVOID;
    glReserved1: array[0..28] of PSIZE_T;
    glReserved2: PVOID;
    glSectionInfo: PVOID;
    glSection: PVOID;
    glTable: PVOID;
    glCurrentRC: PVOID;
    glContext: PVOID;
    LastStatusValue: NTSTATUS;
    StaticUnicodeString: UNICODE_STRING;
    StaticUnicodeBuffer: array[0..260] of WCHAR;
    DeallocationStack: PVOID;
    TlsSlots: array[0..63] of PVOID;
    TlsLinks: LIST_ENTRY;
    Vdm: PVOID;
    ReservedForNtRpc: PVOID;
    DbgSsReserved: array[0..1] of PVOID;

    {$IFDEF WINVER >= $0502} // NTDDI_WS03
    HardErrorMode: ULONG;
    {$ELSE}
    HardErrorsAreDisabled: ULONG;
    {$ENDIF}

    {$IFDEF WINVER >= $0600} // NTDDI_LONGHORN
    Instrumentation: array[0..(13 - SizeOf(TGUID) div SizeOf(PVOID) - 1)] of PVOID;
    ActivityId: TGUID;
    SubProcessTag: PVOID;
    EtwLocalData: PVOID;
    EtwTraceData: PVOID;
    {$ELSE}
      {$IFDEF WINVER >= $0502} // NTDDI_WS03
      Instrumentation: array[0..13] of PVOID;
      SubProcessTag: PVOID;
      EtwLocalData: PVOID;
      {$ELSE}
      Instrumentation: array[0..15] of PVOID;
      {$ENDIF}
    {$ENDIF}

    WinSockData: PVOID;
    GdiBatchCount: ULONG;

    {$IFDEF WINVER >= $0600} // NTDDI_LONGHORN
    SpareBool0: BOOLEAN;
    SpareBool1: BOOLEAN;
    SpareBool2: BOOLEAN;
    {$ELSE}
    InDbgPrint: BOOLEAN;
    FreeStackOnTermination: BOOLEAN;
    HasFiberData: BOOLEAN;
    {$ENDIF}

    IdealProcessor: BYTE;

    {$IFDEF WINVER >= $0502} // NTDDI_WS03
    GuaranteedStackBytes: ULONG;
    {$ELSE}
    Spare3: ULONG;
    {$ENDIF}

    ReservedForPerf: PVOID;
    ReservedForOle: PVOID;
    WaitingOnLoaderLock: ULONG;

    {$IFDEF WINVER >= $0600} // NTDDI_LONGHORN
    SavedPriorityState: PVOID;
    SoftPatchPtr1: ULONG_PTR;
    ThreadPoolData: ULONG_PTR;
    {$ELSE}
      {$IFDEF WINVER >= $0502} // NTDDI_WS03
      SparePointer1: ULONG_PTR;
      SoftPatchPtr1: ULONG_PTR;
      SoftPatchPtr2: ULONG_PTR;
      {$ELSE}
      Wx86Thread: Wx86ThreadState;
      {$ENDIF}
    {$ENDIF}

    TlsExpansionSlots: ^PVOID;

    {$IFDEF WIN64}
    DeallocationBStore: PVOID;
    BStoreLimit: PVOID;
    {$ENDIF}

    ImpersonationLocale: ULONG;
    IsImpersonating: ULONG;
    NlsCache: PVOID;
    pShimData: PVOID;
    HeapVirtualAffinity: ULONG;
    CurrentTransactionHandle: THandle;
    ActiveFrame: PTEB_ACTIVE_FRAME;

    {$IFDEF WINVER >= $0502} // NTDDI_WS03
    FlsData: PVOID;
    {$ENDIF}

    {$IFDEF WINVER >= $0600} // NTDDI_LONGHORN
    PreferredLangauges: PVOID;
    UserPrefLanguages: PVOID;
    MergedPrefLanguages: PVOID;
    MuiImpersonation: ULONG;

    case Integer of
      0: (CrossTebFlags: USHORT);
      1: (SpareCrossTebFlags: USHORT);

    case Integer of
      0: (SameTebFlags: USHORT);
      1: (
        DbgSafeThunkCall: 1;
        DbgInDebugPrint: 1;
        DbgHasFiberData: 1;
        DbgSkipThreadAttach: 1;
        DbgWerInShipAssertCode: 1;
        DbgIssuedInitialBp: 1;
        DbgClonedThread: 1;
        SpareSameTebBits: 9);

    TxnScopeEntercallback: PVOID;
    TxnScopeExitCAllback: PVOID;
    TxnScopeContext: PVOID;
    LockCount: ULONG;
    ProcessRundown: ULONG;
    LastSwitchTime: ULONG64;
    TotalSwitchOutTime: ULONG64;
    WaitReasonBitMap: LARGE_INTEGER;
    {$ELSE}
    SafeThunkCall: BOOLEAN;
    BooleanSpare: array[0..2] of BOOLEAN;
    {$ENDIF}
  end;
  TEB = _TEB;
  PTEB = ^TEB;

type
  _LDR_DATA_TABLE_ENTRY = record
    InLoadOrderLinks: LIST_ENTRY;
    InMemoryOrderLinks: LIST_ENTRY;
    InInitializationOrderLinks: LIST_ENTRY;
    DllBase: PVOID;
    EntryPoint: PVOID;
    SizeOfImage: ULONG;
    FullDllName: UNICODE_STRING;
    BaseDllName: UNICODE_STRING;
    Flags: ULONG;
    LoadCount: WORD;
    TlsIndex: WORD;
    case Byte of                   // Changed to Byte for first case
      0: (HashLinks: LIST_ENTRY);
      1: (
         SectionPointer: PVOID;
         CheckSum: ULONG;
         case Word of              // Changed to Word for second case
           0: (TimeDateStamp: ULONG);
           1: (LoadedImports: PVOID);
           2: (                    // Added fields after unions in a third variant
              EntryPointActivationContext: PACTIVATION_CONTEXT;
              PatchInformation: PVOID;
              ForwarderLinks: LIST_ENTRY;
              ServiceTagLinks: LIST_ENTRY;
              StaticLinks: LIST_ENTRY
           )
      )
  end;
  LDR_DATA_TABLE_ENTRY = _LDR_DATA_TABLE_ENTRY;
  PLDR_DATA_TABLE_ENTRY = ^LDR_DATA_TABLE_ENTRY;

type
 _OBJECT_ATTRIBUTES = record
   Length: ULONG;
   RootDirectory: PVOID;
   ObjectName: PUNICODE_STRING;
   Attributes: ULONG;
   SecurityDescriptor: PVOID;
   SecurityQualityOfService: PVOID;
 end;
 OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES;
 POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;

 _INITIAL_TEB = record
   StackBase: PVOID;
   StackLimit: PVOID;
   StackCommit: PVOID;
   StackCommitMax: PVOID;
   StackReserved: PVOID;
 end;
 INITIAL_TEB = _INITIAL_TEB;
 PINITIAL_TEB = ^INITIAL_TEB;

 type
  IMAGE_DOS_HEADER = record
    e_magic: WORD;                     // Magic number
    e_cblp: WORD;                      // Bytes on last page of file
    e_cp: WORD;                        // Pages in file
    e_crlc: WORD;                      // Relocations
    e_cparhdr: WORD;                   // Size of header in paragraphs
    e_minalloc: WORD;                  // Minimum extra paragraphs needed
    e_maxalloc: WORD;                  // Maximum extra paragraphs needed
    e_ss: WORD;                        // Initial (relative) SS value
    e_sp: WORD;                        // Initial SP value
    e_csum: WORD;                      // Checksum
    e_ip: WORD;                        // Initial IP value
    e_cs: WORD;                        // Initial (relative) CS value
    e_lfarlc: WORD;                    // File address of relocation table
    e_ovno: WORD;                      // Overlay number
    e_res: array[0..3] of WORD;        // Reserved words
    e_oemid: WORD;                     // OEM identifier (for e_oeminfo)
    e_oeminfo: WORD;                   // OEM information; e_oemid specific
    e_res2: array[0..9] of WORD;       // Reserved words
    e_lfanew: LONG;                    // File address of new exe header
  end;
  PIMAGE_DOS_HEADER = ^IMAGE_DOS_HEADER;

  IMAGE_DATA_DIRECTORY = record
    VirtualAddress: DWORD;
    Size: DWORD;
  end;
  PIMAGE_DATA_DIRECTORY = ^IMAGE_DATA_DIRECTORY;

  IMAGE_OPTIONAL_HEADER = record
    Magic: WORD;
    MajorLinkerVersion: BYTE;
    MinorLinkerVersion: BYTE;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    {$IFDEF WIN64}
    ImageBase: ULONGLONG;
    {$ELSE}
    BaseOfData: DWORD;
    ImageBase: DWORD;
    {$ENDIF}
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: WORD;
    MinorOperatingSystemVersion: WORD;
    MajorImageVersion: WORD;
    MinorImageVersion: WORD;
    MajorSubsystemVersion: WORD;
    MinorSubsystemVersion: WORD;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: WORD;
    DllCharacteristics: WORD;
    {$IFDEF WIN64}
    SizeOfStackReserve: ULONGLONG;
    SizeOfStackCommit: ULONGLONG;
    SizeOfHeapReserve: ULONGLONG;
    SizeOfHeapCommit: ULONGLONG;
    {$ELSE}
    SizeOfStackReserve: DWORD;
    SizeOfStackCommit: DWORD;
    SizeOfHeapReserve: DWORD;
    SizeOfHeapCommit: DWORD;
    {$ENDIF}
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: array[0..15] of IMAGE_DATA_DIRECTORY;
  end;
  PIMAGE_OPTIONAL_HEADER = ^IMAGE_OPTIONAL_HEADER;

  IMAGE_FILE_HEADER = record
    Machine: WORD;
    NumberOfSections: WORD;
    TimeDateStamp: DWORD;
    PointerToSymbolTable: DWORD;
    NumberOfSymbols: DWORD;
    SizeOfOptionalHeader: WORD;
    Characteristics: WORD;
  end;
  PIMAGE_FILE_HEADER = ^IMAGE_FILE_HEADER;

  IMAGE_NT_HEADERS = record
    Signature: DWORD;
    FileHeader: IMAGE_FILE_HEADER;
    OptionalHeader: IMAGE_OPTIONAL_HEADER;
  end;
  PIMAGE_NT_HEADERS = ^IMAGE_NT_HEADERS;

implementation

end.
