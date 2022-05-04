#include "inetchannel.h"
#include "extension.h"
#include "CDetour/detours.h"
#include <string.h>

IVEngineServer *pengine;

StopBadPackets g_SBP;

SMEXT_LINK(&g_SBP);

CDetour* g_pDetour = NULL;

#define SIG_LINUX "_ZN8CNetChan13ProcessPacketEP11netpacket_sb"

bool SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
    GET_V_IFACE_CURRENT(GetEngineFactory, pengine, IVEngineServer, INTERFACEVERSION_VENGINESERVER);
    return true;
}

DETOUR_DECL_MEMBER2(Detour_ProcessPacket, void, netpacket_t*, packet, bool, hasHeader)
{
    printf("test");
    return DETOUR_MEMBER_CALL(Detour_ProcessPacket)(packet, hasHeader);
}

bool SDK_OnLoad(char *error, size_t maxlength, bool late)
{
    CDetourManager::Init(g_pSM->GetScriptingEngine(), 0);


    void * fn = memutils->ResolveSymbol(pengine, SIG_LINUX);
     // fn = (void *)((intptr_t)fn + SIG_LINUX_OFFSET);

    g_pDetour = DETOUR_CREATE_MEMBER(Detour_ProcessPacket, fn);
    return true;
}