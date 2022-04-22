#pragma semicolon 1
#pragma newdecls required


#include <sdktools>
#include <dhooks>
#include <discord>
#include <profiler>



Handle hGameData;

Handle SDKCall_GetPlayerSlot;

Handle profiler;

ConVar sm_max_bad_packets_sec;
ConVar sm_max_bogon_sized_packets_sec;
ConVar sm_max_pps_ratio;
ConVar sm_max_packet_processing_time_msec;

int evilPacketsFor          [MAXPLAYERS+1];
int bogonSizedPacketsFor    [MAXPLAYERS+1];

float proctimeThisSecondFor [MAXPLAYERS+1];
int packets                 [MAXPLAYERS+1];


float TickInterval;
float tps;


// TODO TODO TODO
// Sequence number checking
// 


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
    if (!DHookEnableDetour(hProcessPacketHeader_Detour, true, Detour_ProcessPacketHeaderPost))
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

    /*
        GetPlayerSlot
    */
    StartPrepSDKCall(SDKCall_Raw);
    PrepSDKCall_SetFromConf(hGameData, SDKConf_Virtual, "CBaseClient::GetPlayerSlot");
    PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
    SDKCall_GetPlayerSlot = EndPrepSDKCall();
    if (SDKCall_GetPlayerSlot != INVALID_HANDLE)
    {
        PrintToServer("CBaseClient::GetPlayerSlot set up!");
    }
    else
    {
        SetFailState("Failed to get CBaseClient::GetPlayerSlot offset.");
    }

    sm_max_bad_packets_sec =
    CreateConVar
    (
        "sm_max_bad_packets_sec",
        "25",
        "[StopBadPackets] Max invalid packets a client is allowed to send, per second. Default 25.",
        FCVAR_NONE,
        true,
        0.0,
        false,
        _
    );

    sm_max_bogon_sized_packets_sec =
    CreateConVar
    (
        "sm_max_bogon_sized_packets_sec",
        "25",
        "[StopBadPackets] Max oddly sized packets ( <8 bytes or >2048 bytes ) a client is allowed to send, per second. Default 25.",
        FCVAR_NONE,
        true,
        0.0,
        false,
        _
    );

    sm_max_pps_ratio =
    CreateConVar
    (
        "sm_max_pps_ratio",
        "2.5",
        "[StopBadPackets] Max total packets that the client is allowed to send, as a ratio of the server's tickrate. Default 2.5(x), e.g. a client would have to send 160 packets per second to get kicked on a 64 tick server.",
        FCVAR_NONE,
        true,
        0.0,
        false,
        _
    );

    sm_max_packet_processing_time_msec =
    CreateConVar
    (
        "sm_max_packet_processing_time_msec",
        "50",
        "[StopBadPackets] Max time the client is allowed to make the server spend processing packets, in msec. Default 50.",
        FCVAR_NONE,
        true,
        0.0,
        false,
        _
    );


    CreateTimer(1.0, CheckPackets, _, TIMER_REPEAT);

    TickInterval = GetTickInterval();
    tps = 1 / TickInterval;

    profiler = CreateProfiler();
}

public MRESReturn Detour_ProcessPacketHeaderPost(int pThis, DHookReturn hReturn, DHookParam hParams)
{
    int ret = DHookGetReturn(hReturn);

    // Packet was invalid somehow.
    if (ret == -1)
    {
        int client = GetClientFromThis(pThis);
        if (IsValidClient(client))
        {
            evilPacketsFor[client]++;
        }
    }

    return MRES_Ignored;
}

public MRESReturn Detour_ProcessPacket(int pThis, DHookParam hParams)
{
    StartProfiling(profiler);
    int offset = GameConfGetOffset(hGameData, "Offset_PacketSize");

    // Get size of this packet
    Address netpacket = DHookGetParamAddress(hParams, 1);
    int size = LoadFromAddress((netpacket + view_as<Address>(offset)), NumberType_Int32);

    // sanity check
    if (size < 8 || size >= 2048)
    {
        int client = GetClientFromThis(pThis);
        if (IsValidClient(client))
        {
            bogonSizedPacketsFor[client]++;
            return MRES_Supercede;
        }
    }
    return MRES_Ignored;
}

// this isn't a detour but shut up
public MRESReturn Detour_ProcessPacketPost(int pThis, DHookParam hParams)
{
    StopProfiling(profiler);
    int client = GetClientFromThis(pThis);

    if (IsValidClient(client))
    {
        packets[client]++;
        proctimeThisSecondFor[client] += GetProfilerTime(profiler);
    }
    return MRES_Ignored;
}

public Action CheckPackets(Handle timer)
{
    for (int client = 1; client <= MaxClients; client++)
    {
        if (IsValidClient(client))
        {
            // Packet flood first
            if (GetConVarFloat(sm_max_pps_ratio) > 0.0 && packets[client] >= (tps * GetConVarFloat(sm_max_pps_ratio)))
            {
                // char hookmsg[256];
                // Format(hookmsg, sizeof(hookmsg),
                //     "[StopBadPackets] Client -%L- sent [%i] packets in the last second - 2.5 x the server (%.2f) tps!",
                //     client, ticks[client], tps);
                // Discord_SendMessage("badpackets", hookmsg);

                PrintToServer (        "[StopBadPackets] %N sent %i packets to the server in the last second! Kicking to prevent a server Dos", client, packets[client]);
                PrintToChatAll(        "[StopBadPackets] %N sent %i packets to the server in the last second! Kicking to prevent a server Dos", client, packets[client]);
                PrintToConsole(client, "[StopBadPackets] You sent %i packets to the server in the last second! You have been kicked to prevent a server DoS", packets[client]);
                KickClient    (client, "[StopBadPackets] You sent %i packets to the server in the last second! You have been kicked to prevent a server DoS", packets[client]);
            }

            // Oddly sized packets next
            else if (GetConVarFloat(sm_max_bogon_sized_packets_sec) > 0.0 && bogonSizedPacketsFor[client] >= GetConVarFloat(sm_max_bogon_sized_packets_sec))
            {
                PrintToServer (        "[StopBadPackets] %N sent %i oddly sized packets to the server in the last second! Kicking to prevent a server Dos", client, bogonSizedPacketsFor[client]);
                PrintToChatAll(        "[StopBadPackets] %N sent %i oddly sized packets to the server in the last second! Kicking to prevent a server Dos", client, bogonSizedPacketsFor[client]);
                PrintToConsole(client, "[StopBadPackets] You sent %i oddly sized packets to the server in the last second! You have been kicked to prevent a server DoS", bogonSizedPacketsFor[client]);
                KickClient    (client, "[StopBadPackets] You sent %i oddly sized packets to the server in the last second! You have been kicked to prevent a server DoS", bogonSizedPacketsFor[client]);
            }

            // Invalid packets next
            else if (GetConVarFloat(sm_max_bad_packets_sec) > 0.0 && evilPacketsFor[client] >= GetConVarFloat(sm_max_bad_packets_sec))
            {
                PrintToServer (        "[StopBadPackets] %N sent %i invalid packets to the server in the last second! Kicking to prevent a server Dos", client, evilPacketsFor[client]);
                PrintToChatAll(        "[StopBadPackets] %N sent %i invalid packets to the server in the last second! Kicking to prevent a server Dos", client, evilPacketsFor[client]);
                PrintToConsole(client, "[StopBadPackets] You sent %i invalid packets to the server in the last second! You have been kicked to prevent a server DoS", evilPacketsFor[client]);
                KickClient    (client, "[StopBadPackets] You sent %i invalid packets to the server in the last second! You have been kicked to prevent a server DoS", evilPacketsFor[client]);
            }

            // Processing time last
            else if (GetConVarFloat(sm_max_packet_processing_time_msec) > 0.0 && proctimeThisSecondFor[client] > GetConVarFloat(sm_max_packet_processing_time_msec) / 1000)
            {
                // char hookmsg[256];
                // Format(hookmsg, sizeof(hookmsg),
                //    "[StopBadPackets] Client -%L- spent [%.2fms] over [%i] ticks in the last second processing a packet - sm_max_packet_processing_time_msec = %.2f",
                //    client, proctimeThisSecondFor[client]*1000.0, ticks[client], GetConVarFloat(sm_max_packet_processing_time_msec));
                // Discord_SendMessage("badpackets", hookmsg);

                PrintToServer(         "[StopBadPackets] The server spent %.2fms over %i packets in the past second processing network data from client %N. Kicking to prevent a server DoS",       proctimeThisSecondFor[client]*1000.0, packets[client], client);
                PrintToChatAll(        "[StopBadPackets] The server spent %.2fms over %i packets in the past second processing network data from client %N. Kicking to prevent a server DoS",       proctimeThisSecondFor[client]*1000.0, packets[client], client);
                PrintToConsole(client, "[StopBadPackets] The server spent %.2fms over %i packets in the last second processing your network packets. You have been kicked to prevent a server DoS", proctimeThisSecondFor[client]*1000.0, packets[client]);
                KickClient    (client, "[StopBadPackets] The server spent %.2fms over %i packets in the last second processing your network packets. You have been kicked to prevent a server DoS", proctimeThisSecondFor[client]*1000.0, packets[client]);
            }
            // PrintToServer("%N - %fms.", client, proctimeThisSecondFor[client] * 1000);
            // PrintToServer("%N - %i ticks.", client, ticks[client]);
            // PrintToServer("%N - %i evilpackets.", client, evilPacketsFor[client]);
        }
        resetVals(client);
    }
    return Plugin_Continue;
}

// client join
public void OnClientPutInServer(int client)
{
    resetVals(client);
}

// player left and mapchanges
public void OnClientDisconnect(int client)
{
    resetVals(client);
}

void resetVals(int client)
{
    proctimeThisSecondFor[client]   = 0.0;
    packets[client]                 = 0;
    evilPacketsFor[client]          = 0;
    bogonSizedPacketsFor[client]    = 0;
}

bool IsValidClient(int client)
{
    if
    (
        (0 < client <= MaxClients)
        && IsClientInGame(client)
        && !IsFakeClient(client)
    )
    {
        return true;
    }
    return false;
}

// This looks simple but it took literally 6 hours to figure out
int GetClientFromThis(any pThis)
{
    // sanity check
    if (pThis == Address_Null)
    {
        return -1;
    }
    int offset  = GameConfGetOffset(hGameData, "Offset_MessageHandler");
    Address IClient = DerefPtr(pThis + offset);
    if (IClient == Address_Null)
    {
        return -1;
    }
    int client = SDKCall(SDKCall_GetPlayerSlot, IClient) + 1;
    return client;
}

Address DerefPtr(Address addr)
{
    return view_as<Address>(LoadFromAddress(addr, NumberType_Int32));
}