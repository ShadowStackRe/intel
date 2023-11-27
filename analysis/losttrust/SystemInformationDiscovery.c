int SystemInformationDiscovery()
{
  HWND ActiveWindow; // eax
  HWND Capture; // eax
  HWND ClipboardOwner; // eax
  HWND ClipboardViewer; // eax
  HANDLE CurrentProcess; // eax
  int CurrentProcessId; // eax
  HANDLE CurrentThread; // eax
  int CurrentThreadId; // eax
  int TickCount; // eax
  HWND DesktopWindow; // eax
  HWND Focus; // eax
  int InputState; // eax
  int MessagePos; // eax
  int MessageTime; // eax
  HWND OpenClipboardWindow; // eax
  HANDLE ProcessHeap; // eax
  HWINSTA ProcessWindowStation; // eax
  int QueueStatus; // eax
  struct _STARTUPINFOW StartupInfo; // [esp+0h] [ebp-A8h] BYREF
  struct _MEMORYSTATUS Buffer; // [esp+44h] [ebp-64h] BYREF
  LARGE_INTEGER PerformanceCount; // [esp+64h] [ebp-44h] BYREF
  struct _FILETIME UserTime; // [esp+6Ch] [ebp-3Ch] BYREF
  struct _FILETIME KernelTime; // [esp+74h] [ebp-34h] BYREF
  struct _FILETIME ExitTime; // [esp+7Ch] [ebp-2Ch] BYREF
  struct _FILETIME CreationTime; // [esp+84h] [ebp-24h] BYREF
  struct tagPOINT Point; // [esp+8Ch] [ebp-1Ch] BYREF
  int v27; // [esp+94h] [ebp-14h]
  DWORD v28; // [esp+98h] [ebp-10h] BYREF
  ULONG_PTR MaximumWorkingSetSize; // [esp+9Ch] [ebp-Ch] BYREF
  ULONG_PTR MinimumWorkingSetSize; // [esp+A0h] [ebp-8h] BYREF
  HANDLE hThread; // [esp+A4h] [ebp-4h]

  // Gather system information and encode it
  v27 = dword_44A34C;
  ActiveWindow = GetActiveWindow();
  EncodeValue((int)ActiveWindow);
  Capture = GetCapture();
  EncodeValue((int)Capture);
  ClipboardOwner = GetClipboardOwner();
  EncodeValue((int)ClipboardOwner);
  ClipboardViewer = GetClipboardViewer();
  EncodeValue((int)ClipboardViewer);
  CurrentProcess = GetCurrentProcess();
  EncodeValue((int)CurrentProcess);
  CurrentProcessId = GetCurrentProcessId();
  EncodeValue(CurrentProcessId);
  CurrentThread = GetCurrentThread();
  EncodeValue((int)CurrentThread);
  CurrentThreadId = GetCurrentThreadId();
  EncodeValue(CurrentThreadId);
  TickCount = GetTickCount();
  EncodeValue(TickCount);
  DesktopWindow = GetDesktopWindow();
  EncodeValue((int)DesktopWindow);
  Focus = GetFocus();
  EncodeValue((int)Focus);
  InputState = GetInputState();
  EncodeValue(InputState);
  MessagePos = GetMessagePos();
  EncodeValue(MessagePos);
  MessageTime = GetMessageTime();
  EncodeValue(MessageTime);
  OpenClipboardWindow = GetOpenClipboardWindow();
  EncodeValue((int)OpenClipboardWindow);
  ProcessHeap = GetProcessHeap();
  EncodeValue((int)ProcessHeap);
  ProcessWindowStation = GetProcessWindowStation();
  EncodeValue((int)ProcessWindowStation);
  QueueStatus = GetQueueStatus(0x4BFu);
  EncodeValue(QueueStatus);
  GetCaretPos(&Point);
  EncodeRef((int)&Point, 8);
  GetCursorPos(&Point);
  EncodeRef((int)&Point, 8);
  Buffer.dwLength = 32;
  GlobalMemoryStatus(&Buffer);
  EncodeRef((int)&Buffer, 32);
  hThread = GetCurrentThread();
  GetThreadTimes(hThread, &CreationTime, &ExitTime, &KernelTime, &UserTime);
  EncodeRef((int)&CreationTime, 8);
  EncodeRef((int)&ExitTime, 8);
  EncodeRef((int)&KernelTime, 8);
  EncodeRef((int)&UserTime, 8);
  hThread = GetCurrentProcess();
  GetProcessTimes(hThread, &CreationTime, &ExitTime, &KernelTime, &UserTime);
  EncodeRef((int)&CreationTime, 8);
  EncodeRef((int)&ExitTime, 8);
  EncodeRef((int)&KernelTime, 8);
  EncodeRef((int)&UserTime, 8);
  GetProcessWorkingSetSize(hThread, &MinimumWorkingSetSize, &MaximumWorkingSetSize);
  EncodeValue(MinimumWorkingSetSize);
  EncodeValue(MaximumWorkingSetSize);
  if ( !dword_44A350 )
  {
    StartupInfo.cb = 68;
    GetStartupInfoW(&StartupInfo);
    EncodeRef((int)&StartupInfo, 68);
    dword_44A350 = 1;
  }
  if ( QueryPerformanceCounter(&PerformanceCount) )
  {
    EncodeRef((int)&PerformanceCount, 8);
  }
  else
  {
    v28 = GetTickCount();
    EncodeRef((int)&v28, 4);
  }
  if ( ptrBCRYPTRandomFunc )
  {
    if ( ptrBCRYPTRandomFunc(0, &pbBuffer, 320, 2) )
      return 0;
  }
  else
  {
    // If the Microsoft cryptographic next gen API handler failed to aquire a context
    if ( !cryptoContextStatus )
      return 0;                                 // Do not execute the random number generator
    // Initialize the random number generator using the MS next gen cryptographic API
    if ( !CryptGenRandom(phProv, 0x140u, &pbBuffer) )
    {
      lastErrCode = GetLastError();
      return 0;
    }
    EncodeRef((int)&pbBuffer, 320);
  }
  sub_42E930();
  dword_44A34C = v27;
  return 1;
}