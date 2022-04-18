#include <sdktools>
#include <dhooks>

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
Handle netadr_ToString;

ConVar sm_max_bad_packets_sec;

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
    if (!hProcessPacket_Detour)
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


    // for getting ip address from netpacket*
    StartPrepSDKCall(SDKCall_Raw);
    if (!PrepSDKCall_SetFromConf(hGameData, SDKConf_Signature, "netadr_s::ToString"))
    {
        SetFailState("Failed to get netadr_s::ToString");
    }
    PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_ByValue);
    PrepSDKCall_SetReturnInfo(SDKType_String, SDKPass_Pointer);
    netadr_ToString = EndPrepSDKCall();
    PrintToServer("netadr_s::ToString set up!");



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


}

float pretime;
float posttime;

public MRESReturn Detour_ProcessPacket(int pThis, DHookParam hParams)
{
    LogMessage("h");

    pretime = GetEngineTime();

    // Get size
    Address netpacket = DHookGetParamAddress(hParams, 1);
    int size = LoadFromAddress((netpacket + view_as<Address>(0x34)), NumberType_Int8);
    return MRES_Override;


    // sanity check
    // if (size < 1 || size > 3000)
    if (size != 0)
    {
        return MRES_Supercede;
    }
    return MRES_Ignored;
}

public MRESReturn Detour_ProcessPacketPost(int pThis, DHookParam hParams)
{
    posttime = GetEngineTime();
    LogMessage("h");

    float nowtime = posttime - pretime;

    LogMessage("nowtime %f", nowtime);

    return MRES_Ignored;
}

public MRESReturn Detour_ProcessPacketHeader(int pThis, DHookReturn hReturn, DHookParam hParams)
{
    int ret             = DHookGetReturn(hReturn);
    Address netpacket   = DHookGetParamAddress(hParams, 1);

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
        // Let's get the ip address+port of this evil packet.
        char naughtyaddr[64];

        // Ghidra says:
        // char* ip = netadr_s::ToString((netadr_s *)(this + 0x94), false);

        // So let's just recreate that.
        SDKCall(netadr_ToString, (pThis + 0x94), naughtyaddr, sizeof(naughtyaddr), false);
        // PrintToServer("%s", naughtyaddr);

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

                    if (evilPacketsFor[client] >= GetConVarInt(sm_max_bad_packets_sec))
                    {
                        KickClient(client, "[StopBadPackets] Client %N sent too many invalid packets", client);
                        PrintToServer("[StopBadPackets] Client %N sent too many invalid packets", client);
                    }
                }
            }
        }
    }

    return MRES_Ignored;
}


Action Timer_decr_BadPacket(Handle timer, any userid)
{
    int client = GetClientOfUserId(userid);

    if (IsValidClient(client))
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