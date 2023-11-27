int __cdecl AquireNewCryptoAPIHandle()
{
  DWORD dwErrCode; // [esp+4h] [ebp-4h]

  InitializeCriticalSection(&CriticalSection);
  LoadBCryptDLL();                              // # Step 1.1 dynamically load bcrypt.dll
  lastErrCode = 0;
  if ( !dword_44A348 )
  {
    dword_44A348 = (int)LocalAlloc(0x40u, 0x150u);
    if ( !dword_44A348 )
      goto LABEL_7;
    memset((void *)dword_44A348, 0, 0x140u);
  }
  // # Step 1.2 Obtain a reference to the Windows OS cryptographic next gen provider API
  if ( CryptAcquireContextW(&phProv, 0, L"Microsoft Enhanced Cryptographic Provider v1.0", 1u, 0xF0000040) )
  {
    cryptoContextStatus = 1;
    return 0;
  }
  cryptoContextStatus = 0;
  lastErrCode = GetLastError();
LABEL_7:
  dwErrCode = GetLastError();
  SetLastError(dwErrCode);
  return 1;
}