#ifndef _INITGUID_H
#define _INITGUID_H
#ifndef DEFINE_GUID
#include <basetyps.h>
#endif
#undef DEFINE_GUID
#define DEFINE_GUID(n,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) const GUID n GUID_SECT = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}
#endif
