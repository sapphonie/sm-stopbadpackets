#include <sdktools>
#include <dhooks>
#include <discord>

// each channel packet has 1 byte of FLAG bits
#define PACKET_FLAG_RELIABLE            (1<<0)  // packet contains subchannel stream data
#define PACKET_FLAG_COMPRESSED          (1<<1)  // packet is compressed
#define PACKET_FLAG_ENCRYPTED           (1<<2)  // packet is encrypted
#define PACKET_FLAG_SPLIT               (1<<3)  // packet is split
#define PACKET_FLAG_CHOKED              (1<<4)  // packet was choked by sender
#define PACKET_FLAG_CHALLENGE           (1<<5)  // packet contains challenge number, use to prevent packet injection
#define PACKET_FLAG_IDK                 (1<<6)  // who freakin knows man



int evilPacketsFor[MAXPLAYERS+1];

Handle hGameData;

Handle SDKCall_AddrToString;
Handle SDKCall_GetAddress;

ConVar sm_max_bad_packets_sec;
ConVar sm_max_packet_processing_time_msec;

public void OnPluginStart()
{
    hGameData = LoadGameConfigFile("sm.stopbadpackets");
    if (!hGameData)
    {
        SetFailState("Failed to load sm.stopbadpackets gamedata.");
        return;
    }


    /*
        ProcessPacketHeader
    */
    Handle hProcessPacketHeader_Detour = DHookCreateFromConf(hGameData, "ProcessPacketHeader");
    if (!hProcessPacketHeader_Detour)
    {
        SetFailState("Failed to setup detour for ProcessPacketHeader");
    }

    // post hook
    if (!DHookEnableDetour(hProcessPacketHeader_Detour, true, Detour_ProcessPacketHeader))
    {
        SetFailState("Failed to detour ProcessPacketHeader.");
    }
    PrintToServer("CNetChan::ProcessPacketHeader detoured!");

    /*
        ProcessPacket
    */

    Handle hProcessPacket_Detour     = DHookCreateFromConf(hGameData, "ProcessPacket");
    Handle hProcessPacket_DetourPost = DHookCreateFromConf(hGameData, "ProcessPacket");
    if (!hProcessPacket_Detour || !hProcessPacket_DetourPost)
    {
        SetFailState("Failed to setup detour for ProcessPacket");
    }

    // pre hook
    if (!DHookEnableDetour(hProcessPacket_Detour, false, Detour_ProcessPacket))
    {
        SetFailState("Failed to detour ProcessPacket.");
    }
    PrintToServer("CNetChan::ProcessPacket detoured!");

    // post hook
    if (!DHookEnableDetour(hProcessPacket_DetourPost, true, Detour_ProcessPacketPost))
    {
        SetFailState("Failed to detour ProcessPacket [post]");
    }
    PrintToServer("CNetChan::ProcessPacket hooked!");

    if (GetEngineVersion() != Engine_CSGO)
    {
        // for getting ip address from netpacket*
        StartPrepSDKCall(SDKCall_Raw);
        if (!PrepSDKCall_SetFromConf(hGameData, SDKConf_Signature, "netadr_s::ToString"))
        {
            SetFailState("Failed to get netadr_s::ToString");
        }
        PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_ByValue);
        PrepSDKCall_SetReturnInfo(SDKType_String, SDKPass_Pointer);
        SDKCall_AddrToString = EndPrepSDKCall();
        PrintToServer("netadr_s::ToString set up!");
    }
    else
    {
        int offset = GameConfGetOffset(hGameData, "Offset_ToString");
        StartPrepSDKCall(SDKCall_Raw);
        PrepSDKCall_SetVirtual(offset / 4);
        PrepSDKCall_SetReturnInfo(SDKType_String, SDKPass_Pointer);
        SDKCall_GetAddress = EndPrepSDKCall();
    }

    sm_max_bad_packets_sec =
    CreateConVar
    (
        "sm_max_bad_packets_sec",
        "5",
        "[StopBadPackets] Max invalid packets a client is allowed to send, per second. Default 5.",
        FCVAR_NONE,
        true,
        1.0,
        false,
        _
    );

    sm_max_packet_processing_time_msec =
    CreateConVar
    (
        "sm_max_packet_processing_time_msec",
        "20",
        "[StopBadPackets] Max time the client is allowed to make the server spend processing packets, in msec. Default 5.",
        FCVAR_NONE,
        true,
        1.0,
        false,
        _
    );


}

float preproc_time;
float postproc_time;

int lastTick;
int thisTick;

public MRESReturn Detour_ProcessPacket(int pThis, DHookParam hParams)
{
    // engine time before processing this packet
    preproc_time = GetEngineTime();


    int offset = GameConfGetOffset(hGameData, "Offset_PacketSize");

    // Get size of this packet
    Address netpacket = DHookGetParamAddress(hParams, 1);
    int size = LoadFromAddress((netpacket + view_as<Address>(offset)), NumberType_Int32);

    // LogMessage("size %i", size);

    // sanity check
    if (size < 0 )// || size > 4096)
    {
        char naughtyaddr[64];
        naughtyaddr = GetIPFromThis(pThis);
        for (int client = 1; client <= MaxClients; client++)
        {
            if (IsValidClient(client))
            {
                char ip[64];
                // Pass false so we get the port too!
                GetClientIP(client, ip, sizeof(ip), false);
                // Found them!
                if (StrEqual(ip, naughtyaddr))
                {
                    char hookmsg[256];
                    Format(hookmsg, sizeof(hookmsg), "[StopBadPackets] Client -%L- sent a packet with < 0 size! size: %i", client, size);
                    // Discord_SendMessage("badpackets", hookmsg);

                    // KickClient(client, "[StopBadPackets] Client %N sent a packet with no size!", client);
                    PrintToServer("[StopBadPackets] Client %N sent a packet with no size!", client);
                }
            }
        }
        return MRES_Supercede;
    }
    return MRES_Ignored;
}


float thisProcDelta;
float lastProcDelta;

float lastTotalProc;
float thisTotalProc;

float proctime_ms;
// this isn't a detour but shut up
public MRESReturn Detour_ProcessPacketPost(int pThis, DHookParam hParams)
{
    // engine time after processing this packet
    postproc_time = GetEngineTime();

    lastProcDelta = thisProcDelta;
    thisProcDelta = (postproc_time - preproc_time) * 1000.0;

    lastTick = thisTick;
    thisTick = GetGameTickCount();

    int tickDelta = thisTick - lastTick;

    LogMessage("\
    \n    preproc %f\
    \n    postproc %f\
    \n    lastProcDelta %f\
    \n    thisProcDelta %f\
    \n    lastTick %i\
    \n    thisTick %i\
    \n    tickdelta %i\
    ",
    preproc_time,
    postproc_time,
    lastProcDelta,
    thisProcDelta,
    lastTick,
    thisTick,
    tickDelta);


    lastTotalProc = thisTotalProc;

    if (tickDelta == 0)
    {
        thisTotalProc = thisProcDelta + lastProcDelta + lastTotalProc;
    }
    else
    {
        thisTotalProc = thisProcDelta / tickDelta;
    }

    LogMessage("thisTotalProc %.2f", thisTotalProc);

    return MRES_Ignored;
    // we spent this long processing this packet
    // LogMessage("proctime %.2fms", proctime_ms);

    // 
    if (proctime_ms >= GetConVarFloat(sm_max_packet_processing_time_msec))
    {
        char naughtyaddr[64];
        naughtyaddr = GetIPFromThis(pThis);
        for (int client = 1; client <= MaxClients; client++)
        {
            if (IsValidClient(client))
            {
                char ip[64];
                // Pass false so we get the port too!
                GetClientIP(client, ip, sizeof(ip), false);
                // Found them!
                if (StrEqual(ip, naughtyaddr))
                {
                    char hookmsg[256];
                    Format(hookmsg, sizeof(hookmsg), "[StopBadPackets] Client -%L- took %.2fms to process a packet - sm_max_bad_packets_sec = %.2f", client, proctime_ms, GetConVarFloat(sm_max_packet_processing_time_msec));
                    // Discord_SendMessage("badpackets", hookmsg);

                    // KickClient(client, "[StopBadPackets] Client %N took too long to process a packet", client);
                    PrintToServer("[StopBadPackets] Client %N took too long to process a packet", client);
                }
            }
        }

    }

    return MRES_Ignored;
}

public MRESReturn Detour_ProcessPacketHeader(int pThis, DHookReturn hReturn, DHookParam hParams)
{
    int ret             = DHookGetReturn(hReturn);
    // Address netpacket   = DHookGetParamAddress(hParams, 1);

    /*
    char flags[64];
    if (ret & PACKET_FLAG_RELIABLE)
    {
        StrCat(flags, sizeof(flags), "RELIABLE ");
    }
    if (ret & PACKET_FLAG_COMPRESSED)
    {
        StrCat(flags, sizeof(flags), "COMPRESSED ");
    }
    if (ret & PACKET_FLAG_ENCRYPTED)
    {
        StrCat(flags, sizeof(flags), "ENCRYPTED ");
    }
    if (ret & PACKET_FLAG_SPLIT)
    {
        StrCat(flags, sizeof(flags), "SPLIT ");
    }
    if (ret & PACKET_FLAG_CHOKED)
    {
        StrCat(flags, sizeof(flags), "CHOKED ");
    }
    if (ret & PACKET_FLAG_CHALLENGE)
    {
        StrCat(flags, sizeof(flags), "CHALLENGE ");
    }
    if (ret & PACKET_FLAG_IDK)
    {
        StrCat(flags, sizeof(flags), "UNKNOWN FLAG ");
    }

    LogMessage("processing packet header %i %s", ret, flags);

    */


    // Packet was invalid somehow.
    if (ret == -1)
    {
        char naughtyaddr[64];
        naughtyaddr = GetIPFromThis(pThis);

        // Now I *could* sdkcall here. But you see, I am lazy.
        // Let's loop thru our clients to see who has this same ip address.
        for (int client = 1; client <= MaxClients; client++)
        {
            if (IsValidClient(client))
            {
                char ip[64];
                // Pass false so we get the port too!
                GetClientIP(client, ip, sizeof(ip), false);
                // Found them!
                if (StrEqual(ip, naughtyaddr))
                {
                    evilPacketsFor[client]++;
                    PrintToServer("[StopBadPackets] Client %N sent an invalid packet. Detections within the last second: %i", client, evilPacketsFor[client]);

                    // expire this detection in 1 second
                    int userid = GetClientUserId(client);
                    CreateTimer(1.0, Timer_decr_BadPacket, userid, TIMER_FLAG_NO_MAPCHANGE);

                    if (evilPacketsFor[client] == 1 || evilPacketsFor[client] % 5 == 0)
                    {
                        char hookmsg[256];
                        Format(hookmsg, sizeof(hookmsg), "[StopBadPackets] Client -%L- sent too many invalid packets [%i]/s - sm_max_bad_packets_sec = %.2f", client, evilPacketsFor[client], GetConVarFloat(sm_max_bad_packets_sec));
                        // Discord_SendMessage("badpackets", hookmsg);
                    }

                    if (evilPacketsFor[client] >= GetConVarFloat(sm_max_bad_packets_sec))
                    {
                        // KickClient(client, "[StopBadPackets] Client %N sent too many invalid packets", client);
                        PrintToServer("[StopBadPackets] Client %N sent too many invalid packets", client);
                    }
                }
            }
        }
    }

    return MRES_Ignored;
}


char[] GetIPFromThis(any pThis)
{
    if (GetEngineVersion() != Engine_CSGO)
    {
        return AdrToString(pThis);
    }
    else
    {
        return GetAddress(pThis);
    }
}

char[] AdrToString(any pThis)
{
    // Let's get the ip address+port of this evil packet.
    char naughtyaddr[64];

    // Ghidra says:
    // char* ip = netadr_s::ToString((netadr_s *)(this + <game offset>), false);
    // So let's just recreate that.

    int offset = GameConfGetOffset(hGameData, "Offset_ToString");
    SDKCall(SDKCall_AddrToString, (pThis + offset), naughtyaddr, sizeof(naughtyaddr));

    PrintToServer("%s", naughtyaddr);
    return naughtyaddr;
}

char[] GetAddress(any pThis)
{
    char naughtyaddr[64];
    SDKCall(SDKCall_GetAddress, pThis, naughtyaddr, sizeof(naughtyaddr));
    PrintToServer("%s", naughtyaddr);

    return naughtyaddr;
}

Action Timer_decr_BadPacket(Handle timer, any userid)
{
    int client = GetClientOfUserId(userid);

    if (client)
    {
        if (evilPacketsFor[client] > 0)
        {
            evilPacketsFor[client]--;
        }
    }
    return Plugin_Handled;
}

// client join
public void OnClientPutInServer(int client)
{
    evilPacketsFor[client] = 0;
}

// player left and mapchanges
public void OnClientDisconnect(int client)
{
    evilPacketsFor[client] = 0;
}

bool IsValidClient(int client)
{
    if
    (
        (0 < client <= MaxClients)
        && IsClientInGame(client)
        && !IsClientInKickQueue(client)
    )
    {
        return true;
    }
    return false;
}

// oh dear god
/**
 * Loads a null-terminated string from the given address.
 * 
 * The function will return an empty string if the address corresponds to a nullptr.  This
 * functionality is present as a workaround for when an SDKCall that expects a char pointer
 * receives a nullptr and attempts to dereference it (see alliedmodders/sourcemod/issues/874).
 * 
 * If it is necessary to differentiate between an empty string and a null pointer, check if addr
 * is null before calling the function, or pass a reference to bIsNullPointer.
 * 
 * @return Number of bytes written.  0 is returned on an empty string or a null pointer.
 */
stock int LoadStringFromAddress(Address addr, char[] buffer, int maxlen,
        bool &bIsNullPointer = false) {
    if (!addr) {
        bIsNullPointer = true;
        return 0;
    }
    
    int c;
    char ch;
    do {
        ch = view_as<int>(LoadFromAddress(addr + view_as<Address>(c), NumberType_Int8));
        buffer[c] = ch;
    } while (ch && ++c < maxlen - 1);
    return c;
}

/**
 * Reads a value stored in a memory address and returns it as an address.
 * This currently assumes a 32-bit platform.
 * 
 * @param addr          Address to a memory location.
 * @return              The value stored in the given address as an Address.
 */
stock Address DereferencePointer(Address addr) {
    // maybe someday we'll do 64-bit addresses
    return view_as<Address>(LoadFromAddress(addr, NumberType_Int32));
}
