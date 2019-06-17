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
    Emsg := 'dll����ʧ�ܣ�' + syserrormessage(GetLastError);
    Exit;
  end;
  AOldMethod := GetProcAddress(dllHandle, PChar(funcName));
  if AOldMethod = nil then
  begin
    Emsg := 'dll��δ�ҵ�����' + funcName;
    Exit;
  end;
  Result := Hook(AOldMethod, ANewMethod);
end;

function TFuncHooker.Hook(AOldMethod, ANewMethod: Pointer): Boolean;
const
  JmpMinOpcLen = 5; //��С��Ҫ�Ŀռ�   jmp          E9
  JmpRefMinOpcLen = 6; //��С��Ҫ�Ŀռ�   jmp []    FF25
var
  dis: TDisassembler;
  I, J: Byte;
  TmpOffset: UINT_PTR;
  disDesc: string;
  MinOpcLen: Byte; //��С��Ҫ�Ŀռ���
  UOldMethod, UNewMethod: UINT_PTR;
  UJmpCallRefData: UINT_PTR; //�ض����jmp��callλ��,����OriginFunc�ռ���棬������󲻻ᳬ��0x40�ֽڣ�
  UOriginFunc: UINT_PTR;     //д��OriginFunc��λ��
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
  //TODO:Ч�����
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
  //����ԭʼ������
  TmpOffset := UOldMethod;
  dis := TDisassembler.Create(SizeOf(Pointer) = 8);
  for I := 0 to 10 do
  begin
    if I >= 8 then
    begin
      Emsg := 'hookλ�ù�����';
      Exit;
    end;
    dis.disassemble(TmpOffset, disDesc);
    if (dis.LastDisassembleData.opcode <> '') and
      ((dis.LastDisassembleData.opcode[1] = 'j') or (dis.LastDisassembleData.opcode[1] = 'c')) then
    begin
      //jmp ��call Ҫ�ض���
      //��ʵ�ʵ�ַ
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
        Emsg := Format('hook����ʧ��!��Ϊ�˺���ǰ%d���ֽڰ���ָ��%s', [MinOpcLen, dis.LastDisassembleData.opcode]);
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
      //ֱ�Ӹ���
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
  //hook����
  VirtualProtect(AOldMethod, $10, PAGE_EXECUTE_READWRITE, dwOldP);
  _OldMethodVal_8 := Puint64(AOldMethod)^;
  if MinOpcLen = JmpMinOpcLen then
  begin
    //ֱ����
    hookData := PUint64(AOldMethod)^ and $FFFFFF0000000000;
    hookData := hookData or $E9;
    hookJmpData := (UNewMethod - UOldMethod - JmpMinOpcLen) and $FFFFFFFF;
    hookData := hookData or (hookJmpData shl 8);
    PUint64(AOldMethod)^ := hookData;
  end
  else
  begin
    //������
    NearPointer := getNearPointer(AOldMethod);
    if NearPointer = nil then
    begin
      Emsg := 'hookʧ�ܣ��޷���ȡԭ���������ڴ棡';
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
      //δ�������������ڴ�
      ReqMem := Pointer(((uint_ptr(mbi.BaseAddress) + $FFFF) shr 16) shl 16);
      if uint_ptr(ReqMem) + $10000 < uint_ptr(mbi.BaseAddress) + mbi.RegionSize then
      begin
        ReqMem := VirtualAlloc(ReqMem, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
        if ReqMem <> nil then
        begin
          Move(PAnsiChar('TFuncHooker.PRIV')^, ReqMem^, $10);
          PWORD(uint_ptr(ReqMem) + $10)^ := 1;    //hook����
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

