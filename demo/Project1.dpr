program Project1;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  Dialogs,
  disassembler in '..\disassembler.pas',
  MakSHooker in '..\MakSHooker.pas';

var
  msgHooker: TFuncHooker;
procedure MyShowMessage(const Msg: string);
var
  OriginFunc: procedure(const Msg: string);
begin
  OriginFunc := msgHooker.OriginFunc;

  OriginFunc('hook ' + Msg);
end;


var
  APImsgHooker: TFuncHooker;
function MyMessageBoxA(h: HWND; lpText, lpCaption: PAnsiChar; uType: UINT): Integer; stdcall;
var
  OriginFunc: function(h: HWND; lpText, lpCaption: PAnsiChar; uType: UINT): Integer; stdcall;
begin
  OriginFunc := APImsgHooker.OriginFunc;

  Result := OriginFunc(h, PAnsiChar(AnsiString('hook ' + lpText)), lpCaption, uType);
end;

begin
  try
    //delphiº¯Êý
    msgHooker := TFuncHooker.Create;
    msgHooker.Hook(@showmessage, @MyShowMessage);
    showmessage('demo');
    msgHooker.unHook;
    showmessage('demo');
    // API
    APImsgHooker:= TFuncHooker.Create;
    APImsgHooker.Hook('user32.dll','MessageBoxA',@MyMessageBoxA);
    MessageBoxA(0, 'Api Demo', 'Title', MB_OK + MB_ICONINFORMATION);
    APImsgHooker.unHook;
    MessageBoxA(0, 'Api Demo', 'Title', MB_OK + MB_ICONINFORMATION);

  except
    on E: Exception do
      Writeln(E.Classname, ': ', E.Message);
  end;
end.

