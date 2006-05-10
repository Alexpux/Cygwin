#ifndef _VPTYPE_H
#define _VPTYPE_H
#if __GNUC__ >= 3
#pragma GCC system_header
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*--- DirectShow Reference - DirectShow Enumerated Types */
typedef enum _AMVP_MODE {
	AMVP_MODE_WEAVE,
	AMVP_MODE_BOBINTERLEAVED,
	AMVP_MODE_BOBNONINTERLEAVED,
	AMVP_MODE_SKIPEVEN,
	AMVP_MODE_SKIPODD
} AMVP_MODE;
typedef enum _AMVP_SELECT_FORMAT_BY {
	AMVP_DO_NOT_CARE,
	AMVP_BEST_BANDWIDTH,
	AMVP_INPUT_SAME_AS_OUTPUT
} AMVP_SELECT_FORMAT_BY;
/*--- DirectShow Reference - DirectShow Structures */
typedef struct _AMVPDIMINFO{
	DWORD dwFieldWidth;
	DWORD dwFieldHeight;
	DWORD dwVBIWidth;
	DWORD dwVBIHeight;
	RECT rcValidRegion;
} AMVPDIMINFO,*LPAMVPDIMINFO;
typedef struct _AMVPDATAINFO{
	DWORD dwSize;
	DWORD dwMicrosecondsPerField;
	AMVPDIMINFO amvpDimInfo;
	DWORD dwPictAspectRatioX;
	DWORD dwPictAspectRatioY;
	BOOL bEnableDoubleClock;
	BOOL bEnableVACT;
	BOOL bDataIsInterlaced;
	LONG lHalfLinesOdd;
	BOOL bFieldPolarityInverted;
	DWORD dwNumLinesInVREF;
	LONG lHalfLinesEven;
	DWORD dwReserved1;
} AMVPDATAINFO,*LPAMVPDATAINFO;
typedef struct _AMVPSIZE{
	DWORD dwWidth;
	DWORD dwHeight;
} AMVPSIZE,*LPAMVPSIZE;

#ifdef __cplusplus
}
#endif
#endif
