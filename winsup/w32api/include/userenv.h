#ifndef _USERENV_H
#define _USERENV_H
#if __GNUC__ >=3
#pragma GCC system_header
#endif

#ifdef __cplusplus
extern "C" {
#endif
#define PI_NOUI (1)
#define PI_APPLYPOLICY (2)
#if (_WIN32_WINNT >= 0x0500)
#define PT_TEMPORARY (1)
#define PT_ROAMING (2)
#define PT_MANDATORY (4)
#endif
typedef struct _PROFILEINFOA {
  DWORD dwSize;
  DWORD dwFlags;
  LPSTR lpUserName;
  LPSTR lpProfilePath;
  LPSTR lpDefaultPath;
  LPSTR lpServerName;
  LPSTR lpPolicyPath;
  HANDLE hProfile;
} PROFILEINFOA, *LPPROFILEINFOA;
typedef struct _PROFILEINFOW {
  DWORD dwSize;
  DWORD dwFlags;
  LPWSTR lpUserName;
  LPWSTR lpProfilePath;
  LPWSTR lpDefaultPath;
  LPWSTR lpServerName;
  LPWSTR lpPolicyPath;
  HANDLE hProfile;
} PROFILEINFOW, *LPPROFILEINFOW;
BOOL WINAPI LoadUserProfileA(HANDLE,LPPROFILEINFOA);
BOOL WINAPI LoadUserProfileW(HANDLE,LPPROFILEINFOW);
BOOL WINAPI UnloadUserProfile(HANDLE,HANDLE);
BOOL WINAPI GetProfilesDirectoryA(LPSTR,LPDWORD);
BOOL WINAPI GetProfilesDirectoryW(LPWSTR,LPDWORD);
BOOL WINAPI GetUserProfileDirectoryA(HANDLE,LPSTR,LPDWORD);
BOOL WINAPI GetUserProfileDirectoryW(HANDLE,LPWSTR,LPDWORD);
BOOL WINAPI CreateEnvironmentBlock(LPVOID*,HANDLE,BOOL);
BOOL WINAPI DestroyEnvironmentBlock(LPVOID);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI DeleteProfileA(LPCSTR,LPCSTR,LPCSTR);
BOOL WINAPI DeleteProfileW(LPCWSTR,LPCWSTR,LPCWSTR);
BOOL WINAPI GetProfileType(DWORD *);
BOOL WINAPI GetAllUsersProfileDirectoryA(LPSTR,LPDWORD);
BOOL WINAPI GetAllUsersProfileDirectoryW(LPWSTR,LPDWORD);
BOOL WINAPI GetDefaultUserProfileDirectoryA(LPSTR,LPDWORD);
BOOL WINAPI GetDefaultUserProfileDirectoryW(LPWSTR,LPDWORD);
BOOL WINAPI ExpandEnvironmentStringsForUserA(HANDLE,LPCSTR,LPSTR,DWORD);
BOOL WINAPI ExpandEnvironmentStringsForUserW(HANDLE,LPCWSTR,LPWSTR,DWORD);
#endif
#if (_WIN32_WINNT >= 0x0600)
HRESULT WINAPI CreateProfile(LPCWSTR,LPCWSTR,LPWSTR,DWORD);
#endif
#ifdef UNICODE
typedef PROFILEINFOW PROFILEINFO;
typedef LPPROFILEINFOW LPPROFILEINFO;
#define LoadUserProfile  LoadUserProfileW
#define GetProfilesDirectory  GetProfilesDirectoryW
#define GetUserProfileDirectory  GetUserProfileDirectoryW
#if (_WIN32_WINNT >= 0x0500)
#define DeleteProfile  DeleteProfileW
#define GetAllUsersProfileDirectory  GetAllUsersProfileDirectoryW
#define GetDefaultUserProfileDirectory  GetDefaultUserProfileDirectoryW
#define ExpandEnvironmentStringsForUser  ExpandEnvironmentStringsForUserW
#endif
#else
typedef PROFILEINFOA PROFILEINFO;
typedef LPPROFILEINFOA LPPROFILEINFO;
#define LoadUserProfile  LoadUserProfileA
#define GetProfilesDirectory  GetProfilesDirectoryA
#define GetUserProfileDirectory  GetUserProfileDirectoryA
#if (_WIN32_WINNT >= 0x0500)
#define DeleteProfile  DeleteProfileA
#define GetAllUsersProfileDirectory  GetAllUsersProfileDirectoryA
#define GetDefaultUserProfileDirectory  GetDefaultUserProfileDirectoryA
#define ExpandEnvironmentStringsForUser  ExpandEnvironmentStringsForUserA
#endif
#endif
#ifdef __cplusplus
}
#endif
#endif /* _USERENV_H */
