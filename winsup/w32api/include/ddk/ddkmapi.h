/*
 * ddkmapi.h
 *
 * DirectDraw support for DxApi function
 *
 * This file is part of the MinGW package.
 *
 * Contributors:
 *   Created by Casper S. Hornstrup <chorns@users.sourceforge.net>
 *
 * THIS SOFTWARE IS NOT COPYRIGHTED
 *
 * This source code is offered for use in the public domain. You may
 * use, modify or distribute it freely.
 *
 * This code is distributed in the hope that it will be useful but
 * WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 * DISCLAMED. This includes but is not limited to warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __DDKMAPI_H
#define __DDKMAPI_H

#if __GNUC__ >=3
#pragma GCC system_header
#endif

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push,4)

#include "ntddk.h"

#if defined(_DXAPI_)
  #define DXAPI DECLSPEC_EXPORT
#else
  #define DXAPI DECLSPEC_IMPORT
#endif

DXAPI
DWORD
FAR PASCAL
DxApi(
  IN DWORD  dwFunctionNum,
  IN LPVOID  lpvInBuffer,
  IN DWORD  cbInBuffer,
  OUT LPVOID  lpvOutBuffer,
  OUT DWORD  cbOutBuffer);

typedef DWORD (FAR PASCAL *LPDXAPI)(
  DWORD  dwFunctionNum,
  LPVOID  lpvInBuffer,
  DWORD  cbInBuffer,
  LPVOID  lpvOutBuffer,
  DWORD  cbOutBuffer);


#define DXAPI_MAJORVERSION                1
#define DXAPI_MINORVERSION                0

#define DD_FIRST_DXAPI                    0x500

#define DD_DXAPI_GETVERSIONNUMBER                 (DD_FIRST_DXAPI)
#define DD_DXAPI_CLOSEHANDLE                      (DD_FIRST_DXAPI+1)
#define DD_DXAPI_OPENDIRECTDRAW                   (DD_FIRST_DXAPI+2)
#define DD_DXAPI_OPENSURFACE                      (DD_FIRST_DXAPI+3)
#define DD_DXAPI_OPENVIDEOPORT                    (DD_FIRST_DXAPI+4)
#define DD_DXAPI_GETKERNELCAPS                    (DD_FIRST_DXAPI+5)
#define DD_DXAPI_GET_VP_FIELD_NUMBER              (DD_FIRST_DXAPI+6)
#define DD_DXAPI_SET_VP_FIELD_NUMBER              (DD_FIRST_DXAPI+7)
#define DD_DXAPI_SET_VP_SKIP_FIELD                (DD_FIRST_DXAPI+8)
#define DD_DXAPI_GET_SURFACE_STATE                (DD_FIRST_DXAPI+9)
#define DD_DXAPI_SET_SURFACE_STATE                (DD_FIRST_DXAPI+10)
#define DD_DXAPI_LOCK                             (DD_FIRST_DXAPI+11)
#define DD_DXAPI_FLIP_OVERLAY                     (DD_FIRST_DXAPI+12)
#define DD_DXAPI_FLIP_VP                          (DD_FIRST_DXAPI+13)
#define DD_DXAPI_GET_CURRENT_VP_AUTOFLIP_SURFACE  (DD_FIRST_DXAPI+14)
#define DD_DXAPI_GET_LAST_VP_AUTOFLIP_SURFACE     (DD_FIRST_DXAPI+15)
#define DD_DXAPI_REGISTER_CALLBACK                (DD_FIRST_DXAPI+16)
#define DD_DXAPI_UNREGISTER_CALLBACK              (DD_FIRST_DXAPI+17)
#define DD_DXAPI_GET_POLARITY                     (DD_FIRST_DXAPI+18)
#define DD_DXAPI_OPENVPCAPTUREDEVICE              (DD_FIRST_DXAPI+19)
#define DD_DXAPI_ADDVPCAPTUREBUFFER               (DD_FIRST_DXAPI+20)
#define DD_DXAPI_FLUSHVPCAPTUREBUFFERS            (DD_FIRST_DXAPI+21)


typedef struct _DDCAPBUFFINFO {
  DWORD  dwFieldNumber;
  DWORD  bPolarity;
  LARGE_INTEGER  liTimeStamp;
  DWORD  ddRVal;
} DDCAPBUFFINFO, FAR * LPDDCAPBUFFINFO;

/* DDADDVPCAPTUREBUFF.dwFlags constants */
#define DDADDBUFF_SYSTEMMEMORY            0x0001
#define DDADDBUFF_NONLOCALVIDMEM          0x0002
#define DDADDBUFF_INVERT                  0x0004

typedef struct _DDADDVPCAPTUREBUFF {
  HANDLE  hCapture;
  DWORD  dwFlags;
  PMDL  pMDL;
  PKEVENT  pKEvent;
  LPDDCAPBUFFINFO  lpBuffInfo;
} DDADDVPCAPTUREBUFF, FAR * LPDDADDVPCAPTUREBUFF;

typedef struct _DDCLOSEHANDLE {
  HANDLE  hHandle;
} DDCLOSEHANDLE, FAR *LPDDCLOSEHANDLE;

typedef struct _DDFLIPOVERLAY {
  HANDLE  hDirectDraw;
  HANDLE  hCurrentSurface;
  HANDLE  hTargetSurface;
  DWORD  dwFlags;
} DDFLIPOVERLAY, FAR *LPDDFLIPOVERLAY;

typedef struct _DDFLIPVIDEOPORT {
  HANDLE  hDirectDraw;
  HANDLE  hVideoPort;
  HANDLE  hCurrentSurface;
  HANDLE  hTargetSurface;
  DWORD  dwFlags;
} DDFLIPVIDEOPORT, FAR *LPDDFLIPVIDEOPORT;

typedef struct _DDGETAUTOFLIPIN {
  HANDLE  hDirectDraw;
  HANDLE  hVideoPort;
} DDGETAUTOFLIPIN, FAR *LPDDGETAUTOFLIPIN;

typedef struct _DDGETAUTOFLIPOUT {
  DWORD  ddRVal;
  HANDLE  hVideoSurface;
  HANDLE  hVBISurface;
  BOOL  bPolarity;
} DDGETAUTOFLIPOUT, FAR *LPDDGETAUTOFLIPOUT;

typedef struct _DDGETPOLARITYIN {
  HANDLE  hDirectDraw;
  HANDLE  hVideoPort;
} DDGETPOLARITYIN, FAR *LPDDGETPOLARITYIN;

typedef struct _DDGETPOLARITYOUT {
  DWORD  ddRVal;
  BOOL  bPolarity;
} DDGETPOLARITYOUT, FAR *LPDDGETPOLARITYOUT;

typedef struct _DDGETSURFACESTATEIN {
  HANDLE  hDirectDraw;
  HANDLE  hSurface;
} DDGETSURFACESTATEIN, FAR *LPDDGETSURFACESTATEIN;

/* DDGETSURFACESTATEOUT.dwStateCaps/dwStateStatus constants */
#define DDSTATE_BOB                       0x0001
#define DDSTATE_WEAVE                     0x0002
#define DDSTATE_EXPLICITLY_SET            0x0004
#define DDSTATE_SOFTWARE_AUTOFLIP         0x0008
#define DDSTATE_SKIPEVENFIELDS            0x0010

typedef struct _DDGETSURFACESTATEOUT {
  DWORD  ddRVal;
  DWORD  dwStateCaps;
  DWORD  dwStateStatus;
} DDGETSURFACESTATEOUT, FAR *LPDDGETSURFACESTATEOUT;

typedef struct _DDGETFIELDNUMIN {
  HANDLE  hDirectDraw;
  HANDLE  hVideoPort;
} DDGETFIELDNUMIN, FAR *LPDDGETFIELDNUMIN;

typedef struct _DDGETFIELDNUMOUT {
  DWORD  ddRVal;
  DWORD  dwFieldNum;
} DDGETFIELDNUMOUT, FAR *LPDDGETFIELDNUMOUT;

typedef struct _DDGETKERNELCAPSOUT {
  DWORD  ddRVal;
  DWORD  dwCaps;
  DWORD  dwIRQCaps;
} DDGETKERNELCAPSOUT, FAR *LPDDGETKERNELCAPSOUT;

typedef struct _DDGETVERSIONNUMBER {
  DWORD  ddRVal;
  DWORD  dwMajorVersion;
  DWORD  dwMinorVersion;
} DDGETVERSIONNUMBER, FAR *LPDDGETVERSIONNUMBER;

typedef struct _DDLOCKIN {
  HANDLE  hDirectDraw;
  HANDLE  hSurface;
} DDLOCKIN, FAR *LPDDLOCKIN;

typedef struct _DDLOCKOUT {
  DWORD  ddRVal;
  DWORD  dwSurfHeight;
  DWORD  dwSurfWidth;
  LONG  lSurfPitch;
  PVOID  lpSurface;
  DWORD  SurfaceCaps;
  DWORD  dwFormatFlags;
  DWORD  dwFormatFourCC;
  DWORD  dwFormatBitCount;
  union {
    DWORD  dwRBitMask;
    DWORD  dwYBitMask;
  };
  union {
    DWORD  dwGBitMask;
    DWORD  dwUBitMask;
  };
  union {
    DWORD  dwBBitMask;
    DWORD  dwVBitMask;
  };
} DDLOCKOUT, FAR *LPDDLOCKOUT;

/* LPDD_NOTIFYCALLBACK.dwFlags constants */
#define DDNOTIFY_DISPLAY_VSYNC            0x0001
#define DDNOTIFY_VP_VSYNC                 0x0002
#define DDNOTIFY_VP_LINE                  0x0004
#define DDNOTIFY_PRERESCHANGE             0x0008
#define DDNOTIFY_POSTRESCHANGE            0x0010
#define DDNOTIFY_PREDOSBOX                0x0020
#define DDNOTIFY_POSTDOSBOX               0x0040
#define DDNOTIFY_CLOSEDIRECTDRAW          0x0080
#define DDNOTIFY_CLOSESURFACE             0x0100
#define DDNOTIFY_CLOSEVIDEOPORT           0x0200
#define DDNOTIFY_CLOSECAPTURE             0x0400

typedef ULONG (FAR PASCAL *LPDD_NOTIFYCALLBACK)(
  DWORD dwFlags,
  PVOID pContext,
  DWORD dwParam1,
  DWORD dwParam2);

typedef struct _DDOPENDIRECTDRAWIN {
  ULONG_PTR  dwDirectDrawHandle;
  LPDD_NOTIFYCALLBACK  pfnDirectDrawClose;
  PVOID  pContext;
} DDOPENDIRECTDRAWIN, FAR *LPDDOPENDIRECTDRAWIN;

typedef struct _DDOPENDIRECTDRAWOUT {
  DWORD  ddRVal;
  HANDLE  hDirectDraw;
} DDOPENDIRECTDRAWOUT, FAR *LPDDOPENDIRECTDRAWOUT;

typedef struct _DDOPENSURFACEIN {
  HANDLE  hDirectDraw;
  ULONG_PTR  dwSurfaceHandle;
  LPDD_NOTIFYCALLBACK  pfnSurfaceClose;
  PVOID  pContext;
} DDOPENSURFACEIN, FAR *LPDDOPENSURFACEIN;

typedef struct _DDOPENSURFACEOUT {
  DWORD  ddRVal;
  HANDLE  hSurface;
} DDOPENSURFACEOUT, FAR *LPDDOPENSURFACEOUT;

typedef struct _DDOPENVIDEOPORTIN {
  HANDLE  hDirectDraw;
  ULONG  dwVideoPortHandle;
  LPDD_NOTIFYCALLBACK  pfnVideoPortClose;
  PVOID  pContext;
} DDOPENVIDEOPORTIN, FAR *LPDDOPENVIDEOPORTIN;

typedef struct _DDOPENVIDEOPORTOUT {
  DWORD  ddRVal;
  HANDLE  hVideoPort;
} DDOPENVIDEOPORTOUT, FAR *LPDDOPENVIDEOPORTOUT;

/* DDOPENVPCAPTUREDEVICEIN.dwFlags constants */
#define DDOPENCAPTURE_VIDEO               0x0001
#define DDOPENCAPTURE_VBI                 0x0002

typedef struct _DDOPENVPCAPTUREDEVICEIN {
  HANDLE  hDirectDraw;
  HANDLE  hVideoPort;
  DWORD  dwStartLine;
  DWORD  dwEndLine;
  DWORD  dwCaptureEveryNFields;
  LPDD_NOTIFYCALLBACK  pfnCaptureClose;
  PVOID  pContext;
  DWORD  dwFlags;
} DDOPENVPCAPTUREDEVICEIN, FAR * LPDDOPENVPCAPTUREDEVICEIN;

typedef struct _DDOPENVPCAPTUREDEVICEOUT {
  DWORD  ddRVal;
  HANDLE  hCapture;
} DDOPENVPCAPTUREDEVICEOUT, FAR * LPDDOPENVPCAPTUREDEVICEOUT;

/* DDREGISTERCALLBACK.dwEvents constants */
#define DDEVENT_DISPLAY_VSYNC             0x0001
#define DDEVENT_VP_VSYNC                  0x0002
#define DDEVENT_VP_LINE                   0x0004
#define DDEVENT_PRERESCHANGE              0x0008
#define DDEVENT_POSTRESCHANGE             0x0010
#define DDEVENT_PREDOSBOX                 0x0020
#define DDEVENT_POSTDOSBOX                0x0040

typedef struct _DDREGISTERCALLBACK {
  HANDLE  hDirectDraw;
  ULONG  dwEvents;
  LPDD_NOTIFYCALLBACK  pfnCallback;
  ULONG_PTR  dwParam1;
  ULONG_PTR  dwParam2;
  PVOID  pContext;
} DDREGISTERCALLBACK, FAR *LPDDREGISTERCALLBACK;

typedef struct _DDSETSURFACETATE {
  HANDLE  hDirectDraw;
  HANDLE  hSurface;
  DWORD  dwState;
  DWORD  dwStartField;
} DDSETSURFACESTATE, FAR *LPDDSETSURFACESTATE;

typedef struct _DDSETFIELDNUM {
  HANDLE  hDirectDraw;
  HANDLE  hVideoPort;
  DWORD  dwFieldNum;
} DDSETFIELDNUM, FAR *LPDDSETFIELDNUM;

typedef struct _DDSETSKIPFIELD {
  HANDLE  hDirectDraw;
  HANDLE  hVideoPort;
  DWORD  dwStartField;
} DDSETSKIPFIELD, FAR *LPDDSETSKIPFIELD;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* __DDKMAPI_H */
