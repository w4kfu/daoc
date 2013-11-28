#ifndef __SENDPACKET_H__
#define __SENDPACKET_H__

#include <stdio.h>

#include "cryptostuff.h"
#include "daoc.h"

#pragma pack(push,1)
struct PacketSend
{
	unsigned short version;				// dw ?
	unsigned short size;				// dw ?
	unsigned short type;				// dw ?
	unsigned char checksum;				// db ?
	unsigned char seq;				// db ?
	unsigned char buf[31996];       // db 31996 dup(?)
};
#pragma pack(pop)

int SendPacket(struct InfoCon *infocon, struct CHPack *packet);

int MemcpyInPacket(CHPack *packet, char *Buffer, int Size);
void SetWordInPacket(CHPack *packet, unsigned short val);
void SendEncKey(struct InfoCon *info);

void SendClientInfo(struct InfoCon *info);

char __cdecl ComputeCheckSum(char *a1, int Size);

#endif // __SENDPACKET_H__