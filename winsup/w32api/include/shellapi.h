#ifndef _SHELLAPI_H
#define _SHELLAPI_H
#if __GNUC__ >= 3
#pragma GCC system_header
#endif

#ifdef __cplusplus
extern "C" {
#endif
#define WINSHELLAPI DECLSPEC_IMPORT
#define ABE_LEFT	0
#define ABE_TOP	1
#define ABE_RIGHT	2
#define ABE_BOTTOM	3
#define SEE_MASK_CLASSNAME	1
#define SEE_MASK_CLASSKEY	3
#define SEE_MASK_IDLIST	4
#define SEE_MASK_INVOKEIDLIST   12
#define SEE_MASK_ICON	16
#define SEE_MASK_HOTKEY	32
#define SEE_MASK_NOCLOSEPROCESS	64
#define SEE_MASK_CONNECTNETDRV	128
#define SEE_MASK_FLAG_DDEWAIT	256
#define SEE_MASK_DOENVSUBST	512
#define SEE_MASK_FLAG_NO_UI	1024
#define SEE_MASK_UNICODE	65536
#define ABM_NEW	0
#define ABM_REMOVE	1
#define ABM_QUERYPOS	2
#define ABM_SETPOS	3
#define ABM_GETSTATE	4
#define ABM_GETTASKBARPOS	5
#define ABM_ACTIVATE	6
#define ABM_GETAUTOHIDEBAR	7
#define ABM_SETAUTOHIDEBAR	8
#define ABM_WINDOWPOSCHANGED	9
#define ABN_STATECHANGE		0
#define ABN_POSCHANGED		1
#define ABN_FULLSCREENAPP	2
#define ABN_WINDOWARRANGE	3
#define NIM_ADD	0
#define NIM_MODIFY	1
#define NIM_DELETE	2
#define NIF_MESSAGE	1
#define NIF_ICON	2
#define NIF_TIP	4
#define SE_ERR_FNF	2
#define SE_ERR_PNF	3
#define SE_ERR_ACCESSDENIED	5
#define SE_ERR_OOM	8
#define SE_ERR_DLLNOTFOUND	32
#define SE_ERR_SHARE	26
#define SE_ERR_ASSOCINCOMPLETE	27
#define SE_ERR_DDETIMEOUT	28
#define SE_ERR_DDEFAIL	29
#define SE_ERR_DDEBUSY	30
#define SE_ERR_NOASSOC	31
#define FO_MOVE	1
#define FO_COPY	2
#define FO_DELETE	3
#define FO_RENAME	4
#define FOF_MULTIDESTFILES	1
#define FOF_CONFIRMMOUSE	2
#define FOF_SILENT	4
#define FOF_RENAMEONCOLLISION	8
#define FOF_NOCONFIRMATION	16
#define FOF_WANTMAPPINGHANDLE	32
#define FOF_ALLOWUNDO	64
#define FOF_FILESONLY	128
#define FOF_SIMPLEPROGRESS	256
#define FOF_NOCONFIRMMKDIR	512
#define FOF_NOERRORUI	1024
#define PO_DELETE 19
#define PO_RENAME 20
#define PO_PORTCHANGE 32
#define PO_REN_PORT 52
#define SHGFI_ICON	256
#define SHGFI_DISPLAYNAME	512
#define SHGFI_TYPENAME	1024
#define SHGFI_ATTRIBUTES	2048
#define SHGFI_ICONLOCATION	4096
#define SHGFI_EXETYPE 8192
#define SHGFI_SYSICONINDEX 16384
#define SHGFI_LINKOVERLAY 32768
#define SHGFI_SELECTED 65536
#define SHGFI_ATTR_SPECIFIED 131072
#define SHGFI_LARGEICON	0
#define SHGFI_SMALLICON	1
#define SHGFI_OPENICON	2
#define SHGFI_SHELLICONSIZE	4
#define SHGFI_PIDL	8
#define SHGFI_USEFILEATTRIBUTES	16
#define SHERB_NOCONFIRMATION 1
#define SHERB_NOPROGRESSUI 2
#define SHERB_NOSOUND 4

typedef WORD FILEOP_FLAGS;
typedef WORD PRINTEROP_FLAGS;
#include <pshpack2.h>
typedef struct _AppBarData {
	DWORD	cbSize;
	HWND	hWnd;
	UINT	uCallbackMessage;
	UINT	uEdge;
	RECT	rc;
	LPARAM lParam;
} APPBARDATA,*PAPPBARDATA;
DECLARE_HANDLE(HDROP);
typedef struct _NOTIFYICONDATAA {
	DWORD cbSize;
	HWND hWnd;
	UINT uID;
	UINT uFlags;
	UINT uCallbackMessage;
	HICON hIcon;
	CHAR szTip[64];
} NOTIFYICONDATAA,*PNOTIFYICONDATAA;
typedef struct _NOTIFYICONDATAW {
	DWORD cbSize;
	HWND hWnd;
	UINT uID;
	UINT uFlags;
	UINT uCallbackMessage;
	HICON hIcon;
	WCHAR szTip[64];
} NOTIFYICONDATAW,*PNOTIFYICONDATAW;
typedef struct _SHELLEXECUTEINFOA {
	DWORD cbSize;
	ULONG fMask;
	HWND hwnd;
	LPCSTR lpVerb;
	LPCSTR lpFile;
	LPCSTR lpParameters;
	LPCSTR lpDirectory;
	int nShow;
	HINSTANCE hInstApp;
	PVOID lpIDList;
	LPCSTR lpClass;
	HKEY hkeyClass;
	DWORD dwHotKey;
	HANDLE hIcon;
	HANDLE hProcess;
} SHELLEXECUTEINFOA,*LPSHELLEXECUTEINFOA;
typedef struct _SHELLEXECUTEINFOW {
	DWORD cbSize;
	ULONG fMask;
	HWND hwnd;
	LPCWSTR lpVerb;
	LPCWSTR lpFile;
	LPCWSTR lpParameters;
	LPCWSTR lpDirectory;
	int nShow;
	HINSTANCE hInstApp;
	PVOID lpIDList;
	LPCWSTR lpClass;
	HKEY hkeyClass;
	DWORD dwHotKey;
	HANDLE hIcon;
	HANDLE hProcess;
} SHELLEXECUTEINFOW,*LPSHELLEXECUTEINFOW;
typedef struct _SHFILEOPSTRUCTA {
	HWND hwnd;
	UINT wFunc;
	LPCSTR pFrom;
	LPCSTR pTo;
	FILEOP_FLAGS fFlags;
	BOOL fAnyOperationsAborted;
	PVOID hNameMappings;
	LPCSTR lpszProgressTitle;
} SHFILEOPSTRUCTA,*LPSHFILEOPSTRUCTA;
typedef struct _SHFILEOPSTRUCTW {
	HWND hwnd;
	UINT wFunc;
	LPCWSTR pFrom;
	LPCWSTR pTo;
	FILEOP_FLAGS fFlags;
	BOOL fAnyOperationsAborted;
	PVOID hNameMappings;
	LPCWSTR lpszProgressTitle;
} SHFILEOPSTRUCTW,*LPSHFILEOPSTRUCTW;
typedef struct _SHFILEINFOA {
	HICON hIcon;
	int iIcon;
	DWORD dwAttributes;
	CHAR szDisplayName[MAX_PATH];
	CHAR szTypeName[80];
} SHFILEINFOA;
typedef struct _SHFILEINFOW {
	HICON hIcon;
	int iIcon;
	DWORD dwAttributes;
	WCHAR szDisplayName[MAX_PATH];
	WCHAR szTypeName[80];
} SHFILEINFOW;
typedef struct _SHQUERYRBINFO {
	DWORD   cbSize;
	__int64 i64Size;
	__int64 i64NumItems;
} SHQUERYRBINFO, *LPSHQUERYRBINFO;
#include <poppack.h>

LPWSTR * WINAPI CommandLineToArgvW(LPCWSTR,int*);
void WINAPI DragAcceptFiles(HWND,BOOL);
void WINAPI DragFinish(HDROP);
UINT WINAPI DragQueryFileA(HDROP,UINT,LPSTR,UINT);
UINT WINAPI DragQueryFileW(HDROP,UINT,LPWSTR,UINT);
BOOL WINAPI DragQueryPoint(HDROP,LPPOINT);
HICON WINAPI ExtractAssociatedIconA(HINSTANCE,LPCSTR,PWORD);
HICON WINAPI ExtractAssociatedIconW(HINSTANCE,LPCWSTR,PWORD);
HICON WINAPI ExtractIconA(HINSTANCE,LPCSTR,UINT);
HICON WINAPI ExtractIconW(HINSTANCE,LPCWSTR,UINT);
UINT WINAPI ExtractIconExA(LPCSTR,int,HICON*,HICON*,UINT);
UINT WINAPI ExtractIconExW(LPCWSTR,int,HICON*,HICON*,UINT);
HINSTANCE WINAPI FindExecutableA(LPCSTR,LPCSTR,LPSTR);
HINSTANCE WINAPI FindExecutableW(LPCWSTR,LPCWSTR,LPWSTR);
UINT WINAPI SHAppBarMessage(DWORD,PAPPBARDATA);
BOOL WINAPI Shell_NotifyIconA(DWORD,PNOTIFYICONDATAA);
BOOL WINAPI Shell_NotifyIconW(DWORD,PNOTIFYICONDATAW);
int WINAPI ShellAboutA(HWND,LPCSTR,LPCSTR,HICON);
int WINAPI ShellAboutW(HWND,LPCWSTR,LPCWSTR,HICON);
HINSTANCE WINAPI ShellExecuteA(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);
HINSTANCE WINAPI ShellExecuteW(HWND,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,INT);
BOOL WINAPI ShellExecuteExA(LPSHELLEXECUTEINFOA);
BOOL WINAPI ShellExecuteExW(LPSHELLEXECUTEINFOW);
int WINAPI SHFileOperationA(LPSHFILEOPSTRUCTA);
int WINAPI SHFileOperationW(LPSHFILEOPSTRUCTW);
void WINAPI SHFreeNameMappings(HANDLE);
DWORD WINAPI SHGetFileInfoA(LPCSTR,DWORD,SHFILEINFOA*,UINT,UINT);
DWORD WINAPI SHGetFileInfoW(LPCWSTR,DWORD,SHFILEINFOW*,UINT,UINT);
HRESULT WINAPI SHQueryRecycleBinA(LPCSTR, LPSHQUERYRBINFO);
HRESULT WINAPI SHQueryRecycleBinW(LPCWSTR, LPSHQUERYRBINFO);
HRESULT WINAPI SHEmptyRecycleBinA(HWND,LPCSTR,DWORD);
HRESULT WINAPI SHEmptyRecycleBinW(HWND,LPCWSTR,DWORD);

#ifdef UNICODE
typedef NOTIFYICONDATAW NOTIFYICONDATA,*PNOTIFYICONDATA;
typedef SHELLEXECUTEINFOW SHELLEXECUTEINFO,*LPSHELLEXECUTEINFO;
typedef SHFILEOPSTRUCTW SHFILEOPSTRUCT,*LPSHFILEOPSTRUCT;
typedef SHFILEINFOW SHFILEINFO;
#define DragQueryFile DragQueryFileW
#define ExtractAssociatedIcon ExtractAssociatedIconW
#define ExtractIcon ExtractIconW
#define ExtractIconEx ExtractIconExW
#define FindExecutable FindExecutableW
#define Shell_NotifyIcon Shell_NotifyIconW
#define ShellAbout ShellAboutW
#define ShellExecute ShellExecuteW
#define ShellExecuteEx ShellExecuteExW
#define SHFileOperation SHFileOperationW
#define SHGetFileInfo SHGetFileInfoW
#define SHQueryRecycleBin SHQueryRecycleBinW
#define SHEmptyRecycleBin SHEmptyRecycleBinW

#else
typedef NOTIFYICONDATAA NOTIFYICONDATA,*PNOTIFYICONDATA;
typedef SHELLEXECUTEINFOA SHELLEXECUTEINFO,*LPSHELLEXECUTEINFO;
typedef SHFILEOPSTRUCTA SHFILEOPSTRUCT,*LPSHFILEOPSTRUCT;
typedef SHFILEINFOA SHFILEINFO;
#define DragQueryFile DragQueryFileA
#define ExtractAssociatedIcon ExtractAssociatedIconA
#define ExtractIcon ExtractIconA
#define ExtractIconEx ExtractIconExA
#define FindExecutable FindExecutableA
#define Shell_NotifyIcon Shell_NotifyIconA
#define ShellAbout ShellAboutA
#define ShellExecute ShellExecuteA
#define ShellExecuteEx ShellExecuteExA
#define SHFileOperation SHFileOperationA
#define SHGetFileInfo SHGetFileInfoA
#define SHQueryRecycleBin SHQueryRecycleBinA
#define SHEmptyRecycleBin SHEmptyRecycleBinA
#endif
#ifdef __cplusplus
}
#endif
#endif
