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
Handle GetAddr;

public void OnPluginStart()
{
    LogMessage("-------------------------->");
    hGameData = LoadGameConfigFile("tf2.stopbadpackets");
    if (!hGameData)
    {
        SetFailState("Failed to load tf2.stopbadpackets gamedata.");
        return;
    }

    Handle hProcessPacketHeader_Detour = DHookCreateFromConf(hGameData, "ProcessPacketHeader");
    if (!hProcessPacketHeader_Detour)
    {
        SetFailState("Failed to setup detour for ProcessPacketHeader");
    }

    if (!DHookEnableDetour(hProcessPacketHeader_Detour, true, Detour_ProcessPacketHeader))
    {
        SetFailState("Failed to detour ProcessPacketHeader.");
    }


    // get ip address from netpacket*
    StartPrepSDKCall(SDKCall_Raw);
    if (!PrepSDKCall_SetFromConf(hGameData, SDKConf_Signature, "netadr_s::ToString"))
    {
        SetFailState("Failed to get netadr_s::ToString");
    }
    PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_ByValue);
    PrepSDKCall_SetReturnInfo(SDKType_String, SDKPass_Pointer);
    GetAddr = EndPrepSDKCall();
    PrintToServer("netadr_s::ToString set up!");


    PrintToServer("CNetChan::ProcessPacketHeader detoured!");
}

public MRESReturn Detour_ProcessPacketHeader(int pThis, DHookReturn hReturn, DHookParam hParams)
{
    int ret = DHookGetReturn(hReturn);
    Address netpacket = DHookGetParamAddress(hParams, 1);

    char naughtyaddr[64];
    // Don't ask questions you aren't prepared to handle the answers to. I don't know why the offset is 0x94. Don't ask me. This is just what ghidra says.
    // Also we pass false so we get the port.
    SDKCall(GetAddr, (pThis + 0x94), naughtyaddr, sizeof(naughtyaddr), false);
    // LogMessage("%s", naughtyaddr);


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
        StrCat(flags, sizeof(flags), "IDK what this flag does ");
    }

    LogMessage("processing packet header %i %s", ret, flags);
    if (ret == -1)
    {
        // Now I *could* sdkcall here. But you see, I am lazy.
        for (int client = 1; client <= MaxClients; client++)
        {
            if (IsClientConnected(client))
            {
                char ip[64];
                // Pass false so we get the port
                GetClientIP(client, ip, sizeof(ip), false);
                // Dats a match homie
                if (StrEqual(ip, naughtyaddr))
                {
                    evilPacketsFor[client]++;
                    LogMessage("client %i had a fucky wucky packet. Detections: %i", client, evilPacketsFor[client]);
                    if (evilPacketsFor[client] > 5)
                    {
                        LogMessage("that's 5 in a row you stupid idiot goodbye");
                        KickClient(client, "client %N had too many fucky wucky packets", client);
                    }
                }
            }
        }
    }

    return MRES_Ignored;
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