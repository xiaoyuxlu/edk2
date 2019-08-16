/**@file

    Since the SEC is the only windows program in our emulation we
  must use a Tiano mechanism to export Win32 APIs to other modules.

  This file export socket related function to UEFI.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "WinInclude.h"
#include <Protocol/EmuSocket.h>

INT32
SecWSAStartup (
  IN  WORD wVersionRequested,
  OUT LPWSADATA lpWSAData
)
{
  return (INT32) WSAStartup (wVersionRequested, lpWSAData);
}

INT32
SecWSACleanup (
  VOID
)
{
  return (INT32) WSACleanup ();
}

INT32
SecWSAGetLastError (
  VOID
)
{
  return (INT32) WSAGetLastError ();
}

SOCKET
Secsocket (
  IN INT32 af,
  IN INT32 type,
  IN INT32 protocol
)
{
  return socket (af, type, protocol);
}

INT32
Secbind (
  IN SOCKET s,
  IN CONST struct sockaddr *addr,
  IN INT32 namelen
)
{
  return bind (s, addr, namelen);
}

INT32
Seclisten (
  IN SOCKET s,
  IN INT32 backlog
)
{
  return (INT32) listen (s, (int) backlog);
}

SOCKET
Secaccept (
  IN SOCKET s,
  OUT struct sockaddr *addr,
  IN OUT INT32 *addrlen
)
{
  return accept (s, addr, (int*) addrlen);
}

INT32
Secconnect (
  IN SOCKET s,
  IN CONST struct sockaddr *name,
  IN INT32 namelen
  )
{
  return (INT32) connect (s, name, (int) namelen);
}

INT32
Secsend (
  IN SOCKET s,
  IN CONST UINT8 * buf,
  IN INT32 len,
  IN INT32 flags
  )
{
  return (INT32) send (s, (const char *) buf, (int) len, (int) flags);
}

INT32
Secrecv (
  IN SOCKET s,
  OUT UINT8 * buf,
  IN INT32 len,
  IN INT32 flags
  )
{
  return (INT32) recv (s, (char *) buf, (int) len, (int) flags);
}

INT32
Secclosesocket (
  IN SOCKET s0
  )
{
  return (INT32) closesocket (s0);
}


EMU_SOCKET_THUNK_PROTOCOL gEmuSocketThunkProtocol = {
  EFI_WIN_NT_SOCKET_THUNK_PROTOCOL_SIGNATURE,
  SecWSAStartup,
  SecWSACleanup,
  SecWSAGetLastError,
  Secsocket,
  Secbind,
  Seclisten,
  Secaccept,
  Secconnect,
  Secsend,
  Secrecv,
  Secclosesocket
};
