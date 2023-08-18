////////////////////////////////////////////////////////////
// AbyssLocker
// https://www.shadowstackre.com/analysis/AbyssLocker
//
// Technique: System Information Discovery
// URL: https://attack.mitre.org/techniques/T1082/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// ...
 cpuID = GetCPUID_AES();                       // Check if AES Instruction set is supported
  GetCPUID_ControlRegs();
  if ( logFD )
  {
    abstime.tv_nsec = 0LL;
    abstime.tv_sec = 1LL;
    sem_timedwait(&sem, &abstime);
    CPUSeededEntropy = GetCPUID_RDRAND();       // Check if the RDRAND is supported
    __fprintf_chk(
      logFD,
      1LL,
      "Mode:%d  Verbose:%d Daemon:%d AESNI:%d RDRAND:%d \n",
      (unsigned int)progArgMode,
      (unsigned int)progArgVerbose,
      (unsigned int)progArgDeamon,
      (unsigned int)cpuID,
      CPUSeededEntropy);
    fflush(logFD);
    sem_post(&sem);
  }

  __int64 GetCPUID()
{
  __int64 result; // rax

  result = sub_4AF2();
  if ( (_DWORD)result )
  {
    _RAX = 1LL;
    __asm { cpuid; Get CPU ID }
    return ((unsigned int)_RCX >> 25) & 1;
  }
  return result;
}

__int64 GetCPUSeededEntropy()
{
  __int64 result; // rax

  result = sub_4AF2();
  if ( (_DWORD)result )
  {
    _RAX = 1LL;
    __asm { cpuid; Get CPU ID }
    return ((unsigned int)_RCX >> 30) & 1;
  }
  return result;
}