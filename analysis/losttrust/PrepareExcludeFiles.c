HLOCAL PrepareExcludeFiles()
{
  HLOCAL result; // eax
  int v1; // eax
  int v2[14]; // [esp+0h] [ebp-4Ch]
  int v3; // [esp+38h] [ebp-14h]
  __int16 *v4; // [esp+3Ch] [ebp-10h]
  __int16 *v5; // [esp+40h] [ebp-Ch]
  unsigned int i; // [esp+44h] [ebp-8h]

  v2[0] = (int)L"autorun.inf";
  v2[1] = (int)L"boot.ini";
  v2[2] = (int)L"bootfont.bin";
  v2[3] = (int)L"bootsect.bak";
  v2[4] = (int)L"desktop.ini";
  v2[5] = (int)L"iconcache.db";
  v2[6] = (int)L"ntldr";
  v2[7] = (int)L"ntuser.dat";
  v2[8] = (int)L"ntuser.dat.log";
  v2[9] = (int)L"ntuser.ini";
  v2[10] = (int)L"thumbs.db";
  v2[11] = (int)L"bootmgr";
  v2[12] = (int)L"!losttrustencoded.txt";
  v2[13] = (int)L"! cynet ransom protection(don't delete)";
  dword_44A35C = 14;
  result = LocalAlloc(0x40u, 0x40u);
  dword_44A358 = (int)result;
  for ( i = 0; i < 0xE; ++i )
  {
    v5 = (__int16 *)v2[i];
    v4 = v5 + 1;
    while ( *v5++ )
      ;
    v3 = v5 - v4;
    v1 = sub_4370D0(v2[i], 2 * v3, 0);
    *(_DWORD *)(dword_44A358 + 4 * i) = v1;
    result = (HLOCAL)(i + 1);
  }
  return result;
}