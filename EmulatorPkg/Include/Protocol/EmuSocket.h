/**@file

 A protocol to export Win32 socket APIs.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __EMU_SOCKET_PROTOCOL_H__
#define __EMU_SOCKET_PROTOCOL_H__

#ifndef FAR
#define FAR
#endif

#define EMU_SOCKET_PROTOCOL_GUID \
  { 0x7418693c, 0x47b7, 0x4abf, { 0xa9, 0x6f, 0xd0, 0xca, 0x25, 0x96, 0x4, 0x98 } }

typedef
INT32
( *WinNtWSAStartup) (
    IN  WORD wVersionRequested,
    OUT LPWSADATA lpWSAData
    );

typedef
INT32
( *WinNtWSACleanup) (
    VOID
    );

typedef
INT32
( *WinNtWSAGetLastError) (
    VOID
    );

typedef
SOCKET
( *WinNtsocket) (
  IN INT32 af,
  IN INT32 type,
  IN INT32 protocol
  );

typedef
INT32
( *WinNtbind) (
  IN SOCKET s,
  IN CONST struct sockaddr *addr,
  IN INT32 namelen
  );

typedef
INT32
( *WinNtlisten) (
  IN SOCKET s,
  IN INT32 backlog
  );

typedef
SOCKET
( *WinNtaccept) (
  IN SOCKET s,
  OUT struct sockaddr *addr,
  IN OUT INT32 *addrlen
  );

typedef
INT32
( *WinNtconnect) (
  IN SOCKET s,
  IN CONST struct sockaddr *name,
  IN INT32 namelen
  );

typedef
INT32
( *WinNtsend) (
  IN SOCKET s,
  IN CONST UINT8 * buf,
  IN INT32 len,
  IN INT32 flags
  );

typedef
INT32
( *WinNtrecv) (
  IN SOCKET s,
  OUT UINT8 * buf,
  IN INT32 len,
  IN INT32 flags
  );

typedef
INT32
( *WinNtclosesocket) (
  IN SOCKET s
  );

#undef FAR

#define EFI_WIN_NT_SOCKET_THUNK_PROTOCOL_SIGNATURE SIGNATURE_32 ('N', 'T', 'S', 'T')

typedef struct {
  UINT64                              Signature;

  //
  // Win32 Socket APIs
  //
  WinNtWSAStartup                     WSAStartup;
  WinNtWSACleanup                     WSACleanup;
  WinNtWSAGetLastError                WSAGetLastError;

  WinNtsocket                         socket;
  WinNtbind                           bind;
  WinNtlisten                         listen;
  WinNtaccept                         accept;
  WinNtconnect                        connect;
  WinNtsend                           send;
  WinNtrecv                           recv;
  WinNtclosesocket                    closesocket;

} EMU_SOCKET_THUNK_PROTOCOL;

extern EMU_SOCKET_THUNK_PROTOCOL gEmuSocketThunkProtocol;

#endif // __EMU_SOCKET_PROTOCOL_H__