////////////////////////////////////////////////////////////
// AbyssLocker
// https://www.shadowstackre.com/analysis/AbyssLocker
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// Attempt to find libcrypto.so deps
libCryptoStatus = FindLibCrypto();
  if ( libCryptoStatus == -1 )
  {
    if ( logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      fputs("Error InitAPI !!!\nExit\n", logFD);
      fflush(logFD);
      sem_post(&sem);
    }
    fputs("Error InitAPI !!!\nExit\n", stderr);
    return libCryptoStatus;
  }


__int64 FindLibCrypto()
{
  __int64 v0; // rcx
  unsigned int v1; // ebx
  char *v2; // rdi
  char **refEVP_MD_CTX_new; // rbp
  int v4; // ebx
  __int64 v5; // r9
  char *addrSymbolEVP_MD_CTX_new; // rax
  const char *v7; // rsi
  char *v8; // rax
  struct timespec abstime; // [rsp+8h] [rbp-130h] BYREF
  char libCryptorRefName[256]; // [rsp+18h] [rbp-120h] BYREF
  unsigned __int64 v12; // [rsp+118h] [rbp-20h]

  v0 = 64LL;
  v1 = 0;
  v12 = __readfsqword(0x28u);
  v2 = libCryptorRefName;
  while ( v0 )
  {
    *(_DWORD *)v2 = 0;
    v2 += 4;
    --v0;
  }
  strcpy(libCryptorRefName, "libcrypto.so");
  while ( 1 )
  {
    handle = dlopen(libCryptorRefName, 2);      // Attempt to get a hndle to the opened the library
    if ( handle )
    {
      refEVP_MD_CTX_new = off_216140;           // EVP_MD_CTX_new
      v4 = 0;
      // Get the address in memory of a symbol from libcrypto.so
      while ( 1 )
      {
        addrSymbolEVP_MD_CTX_new = (char *)dlsym(handle, *refEVP_MD_CTX_new);
        refEVP_MD_CTX_new[2] = addrSymbolEVP_MD_CTX_new;
        if ( !addrSymbolEVP_MD_CTX_new )
        {
          v7 = refEVP_MD_CTX_new[1];
          if ( !v7 )
            break;
          v8 = (char *)dlsym(handle, v7);
          refEVP_MD_CTX_new[2] = v8;
          if ( !v8 )
            break;
        }
        ++v4;
        refEVP_MD_CTX_new += 3;
        if ( v4 == 57 )
          return 1LL;
      }
      if ( !logFD )
        return 0xFFFFFFFFLL;
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(logFD, 1LL, "Error find %s in libcrypto.so\n", off_216140[3 * v4]);
      goto LABEL_16;
    }
    if ( v1 == 21 )
      break;
    v5 = v1++;
    __sprintf_chk(libCryptorRefName, 1LL, 256LL, "%s.%d", "libcrypto.so", v5);
  }
  if ( !logFD )
    return 0xFFFFFFFFLL;
  abstime.tv_nsec = 0LL;
  abstime.tv_sec = 1LL;
  sem_timedwait(&sem, &abstime);
  fputs("libcrypto.so not found\n", logFD);
LABEL_16:
  fflush(logFD);
  sem_post(&sem);
  return 0xFFFFFFFFLL;
}