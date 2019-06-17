unit MakSHooker;

interface

uses
  Windows;

type
  PUINT_PTR = ^UINT_PTR;
  PUint64 = ^Uint64;

  TFuncHooker = class
  private
    const
      OriginFuncSpaceSize = $100;
    var
      _OldMethodAddr :Pointer;
      _OldMethodVal_8 :UInt64;
    function getNearPointer(AOldMethod: Pointer): pointer;
  public
    OriginFunc: Pointer;
    Emsg: string;
    function Hook(dllName, funcName: string; ANewMethod: Pointer): Boolean; overload;
    function Hook(AOldMethod, ANewMethod: Pointer): Boolean; overload;
    constructor Create;
    destructor Destroy; override;
    procedure unHook;
  end;

implementation

uses
  SysUtils, disassembler;

{ TFuncHooker }

constructor TFuncHooker.Create;
var
  dwOldP: Cardinal;
begin
  _OldMethodAddr := nil;
  _OldMethodVal_8 := 0;
  OriginFunc := AllocMem(OriginFuncSpaceSize);
  PUint64(OriginFunc)^ := 0;
  VirtualProtect(OriginFunc, OriginFuncSpaceSize, PAGE_EXECUTE_READWRITE, dwOldP);
end;
destructor TFuncHooker.Destroy;
begin
  unHook;
  FreeMem(OriginFunc);
  inherited;
end;


function TFuncHooker.Hook(dllName, funcName: string; ANewMethod: Pointer): Boolean;
var
  dllHandle: THandle;
  AOldMethod: Pointer;
begin
  Result := False;
  dllHandle := LoadLibrary(PChar(dllName));
  if dllHandle = INVALID_HANDLE_VALUE then
  begin
    Emsg := 'dll加载失败！' + syserrormessage(GetLastError);
    Exit;
  end;
  AOldMethod := GetProcAddress(dllHandle, PChar(funcName));
  if AOldMethod = nil then
  begin
    Emsg := 'dll中未找到函数' + funcName;
    Exit;
  end;
  Result := Hook(AOldMethod, ANewMethod);
end;

function TFuncHooker.Hook(AOldMethod, ANewMethod: Pointer): Boolean;
const
  JmpMinOpcLen = 5; //最小需要的空间   jmp          E9
  JmpRefMinOpcLen = 6; //最小需要的空间   jmp []    FF25
var
  dis: TDisassembler;
  I, J: Byte;
  TmpOffset: UINT_PTR;
  disDesc: string;
  MinOpcLen: Byte; //最小需要的空间数
  UOldMethod, UNewMethod: UINT_PTR;
  UJmpCallRefData: UINT_PTR; //重定向的jmp和call位置,（在OriginFunc空间后面，复制最大不会超过0x40字节）
  UOriginFunc: UINT_PTR;     //写入OriginFunc的位置
  dwOldP: Cardinal;
  hookData: UInt64;
  hookJmpData: UInt64;
  NearPointer: Pointer;
begin
  if _OldMethodVal_8>0 then
  begin
    Result := False;
    Exit;
  end;

  _OldMethodAddr := AOldMethod;
  Result := False;
  //TODO:效验入参
  UOriginFunc := UINT_PTR(OriginFunc);
  UJmpCallRefData := UOriginFunc + OriginFuncSpaceSize - 8;
  UOldMethod := UINT_PTR(AOldMethod);
  UNewMethod := UINT_PTR(ANewMethod);
  if UOldMethod > UNewMethod then
  begin
    if (UOldMethod - UNewMethod) > $7FFF0000 then
    begin
      MinOpcLen := JmpRefMinOpcLen;
    end
    else
    begin
      MinOpcLen := JmpMinOpcLen;
    end;
  end
  else
  begin
    if (UNewMethod - UOldMethod) > $7FFF0000 then
    begin
      MinOpcLen := JmpRefMinOpcLen;
    end
    else
    begin
      MinOpcLen := JmpMinOpcLen;
    end;
  end;
  //备份原始函数链
  TmpOffset := UOldMethod;
  dis := TDisassembler.Create(SizeOf(Pointer) = 8);
  for I := 0 to 10 do
  begin
    if I >= 8 then
    begin
      Emsg := 'hook位置过长！';
      Exit;
    end;
    dis.disassemble(TmpOffset, disDesc);
    if (dis.LastDisassembleData.opcode <> '') and
      ((dis.LastDisassembleData.opcode[1] = 'j') or (dis.LastDisassembleData.opcode[1] = 'c')) then
    begin
      //jmp 和call 要重定向
      //存实际地址
      PUINT_PTR(UJmpCallRefData)^ := dis.LastDisassembleData.parameterValue;
      if (dis.LastDisassembleData.opcode = 'call') then
      begin
        PWord(UOriginFunc)^ := $15FF;
        UOriginFunc := UOriginFunc + 2;
      end
      else if (dis.LastDisassembleData.opcode = 'jmp') then
      begin
        PWord(UOriginFunc)^ := $25FF;
        UOriginFunc := UOriginFunc + 2;
      end
      else
      begin
        Emsg := Format('hook函数失败!因为此函数前%d个字节包含指令%s', [MinOpcLen, dis.LastDisassembleData.opcode]);
        exit;
      end;
      {$IF SIZEOF(Pointer)=4}
      PDWORD(UOriginFunc)^ := UJmpCallRefData;
      {$ELSE}
      PDWORD(UOriginFunc)^ := UJmpCallRefData - UOriginFunc - 4;
      {$IFEND}
      UOriginFunc := UOriginFunc + 4;
      UJmpCallRefData := UJmpCallRefData - 8;
    end
    else
    begin
      //直接复制
      for J := 0 to Length(dis.LastDisassembleData.Bytes) - 1 do
      begin
        PByte(UOriginFunc + J)^ := dis.LastDisassembleData.Bytes[J];
      end;
      UOriginFunc := UOriginFunc + Cardinal(Length(dis.LastDisassembleData.Bytes));
    end;

    if TmpOffset - UOldMethod >= MinOpcLen then
    begin
      Break;
    end;
  end;
  dis.Free;

  PWord(UOriginFunc)^ := $25FF;
  {$IF SIZEOF(Pointer)=4}
  PDWORD(UOriginFunc + 2)^ := UOriginFunc + 6;
  {$ELSE}
  PDWORD(UOriginFunc + 2)^ := 0;
  {$IFEND}
  PUINT_PTR(UOriginFunc + 6)^ := TmpOffset;
  //hook函数
  VirtualProtect(AOldMethod, $10, PAGE_EXECUTE_READWRITE, dwOldP);
  _OldMethodVal_8 := Puint64(AOldMethod)^;
  if MinOpcLen = JmpMinOpcLen then
  begin
    //直接跳
    hookData := PUint64(AOldMethod)^ and $FFFFFF0000000000;
    hookData := hookData or $E9;
    hookJmpData := (UNewMethod - UOldMethod - JmpMinOpcLen) and $FFFFFFFF;
    hookData := hookData or (hookJmpData shl 8);
    PUint64(AOldMethod)^ := hookData;
  end
  else
  begin
    //跳引用
    NearPointer := getNearPointer(AOldMethod);
    if NearPointer = nil then
    begin
      Emsg := 'hook失败，无法获取原函数附近内存！';
      exit;
    end;
    PUINT_PTR(NearPointer)^ := UNewMethod;
    hookData := PUint64(AOldMethod)^ and $FFFF000000000000;
    hookData := hookData or $25FF;
    {$IF SIZEOF(Pointer)=4}
    hookJmpData := Uint_ptr(NearPointer);
    {$ELSE}
    hookJmpData := (Uint_ptr(NearPointer) - UOldMethod - MinOpcLen) and $FFFFFFFF;
    {$IFEND}
    hookData := hookData or (hookJmpData shl 16);
    PUint64(AOldMethod)^ := hookData;
  end;
end;

procedure TFuncHooker.unHook;
begin
  if _OldMethodVal_8 > 0 then
    PUint64(_OldMethodAddr)^ := _OldMethodVal_8;
end;

function TFuncHooker.getNearPointer(AOldMethod: Pointer): Pointer;
var
  mbi: TMemoryBasicInformation;
  currentBaseAddress: Pointer;
  ReqMem: Pointer;
  hookerCnt: word;
begin
  Result := nil;
  currentBaseAddress := AOldMethod;
  while VirtualQueryEx(GetCurrentProcess, currentBaseAddress, mbi, sizeof(mbi)) <> 0 do
  begin
    if (mbi.State = MEM_FREE) and (mbi.RegionSize > $10000) then
    begin
      //未分配就申请这块内存
      ReqMem := Pointer(((uint_ptr(mbi.BaseAddress) + $FFFF) shr 16) shl 16);
      if uint_ptr(ReqMem) + $10000 < uint_ptr(mbi.BaseAddress) + mbi.RegionSize then
      begin
        ReqMem := VirtualAlloc(ReqMem, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
        if ReqMem <> nil then
        begin
          Move(PAnsiChar('TFuncHooker.PRIV')^, ReqMem^, $10);
          PWORD(uint_ptr(ReqMem) + $10)^ := 1;    //hook数量
          Result := Pointer(uint_ptr(ReqMem) + $20);
          Break;
        end;
      end;
    end
    else if (mbi.State = MEM_COMMIT) and (mbi.Type_9 = MEM_PRIVATE) and (mbi.Protect = PAGE_READWRITE) then
    begin
      if CompareMem(mbi.AllocationBase, PAnsiChar('TFuncHooker.PRIV'), $10) then
      begin
        ReqMem := mbi.AllocationBase;
        hookerCnt := PWORD(uint_ptr(ReqMem) + $10)^;
        PWORD(uint_ptr(ReqMem) + $10)^ := hookerCnt + 1;
        Result := Pointer(uint_ptr(ReqMem) + $20 + (hookerCnt * SizeOf(Pointer)));
        Break;
      end;
    end;
    currentBaseAddress := Pointer(uint_ptr(mbi.BaseAddress) + mbi.RegionSize);
  end;
end;

end.

