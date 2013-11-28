#ifndef RECVPACKET_H_
#define RECVPACKET_H_

#include "daoc.h"

void GetDWORDInPacket(struct CHPack *packet, unsigned int *a2);
void GetCharInPacket(struct CHPack *pack, char *val);
void GetWordInPacket(struct CHPack *pack, unsigned short *val);
void GetStringInPacket(struct CHPack *pack, char *val, unsigned int MaxSize);
void HandlePacket(struct InfoCon *info, struct CHPack *pack);
void ParsePacket(struct InfoCon *info, struct Packet *packet);

#endif // RECVPACKET_H_