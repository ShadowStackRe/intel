int __cdecl EnumerateShareLocations(LPNETRESOURCEW lpNetResource)
{
  int result; // eax
  __int16 *v2; // [esp+Ch] [ebp-44h]
  HANDLE hEnum; // [esp+14h] [ebp-3Ch] BYREF
  SIZE_T v4; // [esp+18h] [ebp-38h]
  int v5; // [esp+1Ch] [ebp-34h]
  DWORD cCount[2]; // [esp+20h] [ebp-30h] BYREF
  DWORD v7; // [esp+28h] [ebp-28h]
  __int16 *v8; // [esp+2Ch] [ebp-24h]
  DWORD BufferSize; // [esp+30h] [ebp-20h] BYREF
  WCHAR *v10; // [esp+34h] [ebp-1Ch]
  WCHAR *v11; // [esp+38h] [ebp-18h]
  __int16 *v12; // [esp+3Ch] [ebp-14h]
  LPVOID lpBuffer; // [esp+40h] [ebp-10h]
  DWORD i; // [esp+44h] [ebp-Ch]
  WCHAR v15; // [esp+4Ah] [ebp-6h]
  __int16 v17; // [esp+4Eh] [ebp-2h]

  // Create a handle to the open connected shared drives
  result = WNetOpenEnumW(1u, 1u, 0, lpNetResource, &hEnum);
  if ( !result )
  {
    BufferSize = 4096;
    cCount[1] = 4112;
    lpBuffer = LocalAlloc(0x40u, 0x1010u);
    if ( lpBuffer )
    {
      do
      {
        cCount[0] = -1;
        // Continue to enumerate shared drives (does not find hidden shares)
        v7 = WNetEnumResourceW(hEnum, cCount, lpBuffer, &BufferSize);
        if ( v7 )
        {
          if ( v7 != 259 )
            break;
        }
        else
        {
          for ( i = 0; i < cCount[0]; ++i )
          {
            if ( (*((_DWORD *)lpBuffer + 8 * i + 3) & 2) != 0 )
            {
              EnumerateShareLocations((LPNETRESOURCEW)lpBuffer + i);
            }
            else
            {
              v12 = (__int16 *)*((_DWORD *)lpBuffer + 8 * i + 5);
              v2 = v12 + 1;
              while ( *v12++ )
                ;
              v5 = v12 - v2 + 10;
              if ( ((2 * v5 + 16) & 0xFFFFFFF0) >= 0x10 )
                v4 = (2 * v5 + 16) & 0xFFFFFFF0;
              else
                v4 = 16;
              dword_44A380[dword_44C380] = (PCWSTR)LocalAlloc(0x40u, v4);
              if ( dword_44A380[dword_44C380] )
              {
                v8 = (__int16 *)*((_DWORD *)lpBuffer + 8 * i + 5);
                v11 = (WCHAR *)dword_44A380[dword_44C380];
                do
                {
                  v17 = *v8;
                  *v11 = v17;
                  ++v8;
                  ++v11;
                }
                while ( v17 );
                v10 = (WCHAR *)(dword_44A380[dword_44C380] - 1);
                do
                {
                  v15 = v10[1];
                  ++v10;
                }
                while ( v15 );
                *(_DWORD *)v10 = 92;
                ++dword_44C380;
              }
            }
          }
        }
      }
      while ( v7 != 259 );
      LocalFree(lpBuffer);
    }
    // CLose the connection to the share handle
    return WNetCloseEnum(hEnum);
  }
  return result;
}