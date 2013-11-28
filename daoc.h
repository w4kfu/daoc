#ifndef DAOC_H
#define DAOC_H

#include <stdio.h>

#define _WINSOCKAPI_ 
#include <windows.h>
#include <winsock2.h>

#include "cryptostuff.h"
#include "sendpacket.h"
#include "dbg.h"
#include "protocol.h"
#include "recvpacket.h"

#define SYMKEY_SIZE 256

#define ACCOUNT_NAME "testoy"
#define ACCOUNT_PASSWORD "suc3SUCEsuc3"

#define ROL8(n, r)  ( ((unsigned char)(n) << (r)) | ((unsigned char)(n) >> ( 8 - (r))) ) /* only works for uint8_t */
#define ROL16(n, r) ( ((unsigned short)(n) << (r)) | ((unsigned short)(n) >> (16 - (r))) ) /* only works for uint16_t */

struct InfoCon
{
	SOCKET sock;
	unsigned char sym_sbox[SYMKEY_SIZE];
	int sym_keyset;
	int sequence;
};

#pragma pack(push,1)
struct CHPack
{
	unsigned int field_0;
	unsigned int MsgType;
	unsigned int pos;
	unsigned int PacketSize;
	unsigned int CheckSum;
	unsigned int field_14;
	char buf[32000];
};
#pragma pack(pop)

#pragma pack(push,1)
struct Packet
{
	unsigned int field_0;
	unsigned int field_4;
	unsigned int field_8;
	unsigned int field_C;
	unsigned int field_10;
	unsigned int NS_IsConnect;
	unsigned int field_18;
	unsigned int field_1C;
	unsigned short LengthPacket;
	unsigned short field_22;
	unsigned int field_24;
	unsigned int field_28;
	unsigned int field_2C;
	unsigned int field_30;
	unsigned int field_34;
	unsigned int field_38;
	unsigned int field_3C;
	unsigned int field_40;
	unsigned int field_44;
	unsigned int field_48;
	unsigned int field_4C;
	unsigned int field_50;
	unsigned int field_54;
	unsigned int field_58;
	unsigned int field_5C;
	unsigned int field_60;
	unsigned int field_64;
	unsigned int field_68;
	unsigned int field_6C;
	unsigned int field_70;
	unsigned int field_74;
	unsigned int field_78;
	unsigned int field_7C;
	unsigned int field_80;
	unsigned int field_84;
	unsigned int field_88;
	unsigned int field_8C;
	unsigned int field_90;
	unsigned int field_94;
	unsigned int field_98;
	unsigned int field_9C;
	unsigned int field_A0;
	unsigned int field_A4;
	unsigned int field_A8;
	unsigned int field_AC;
	unsigned int field_B0;
	unsigned int field_B4;
	unsigned int field_B8;
	unsigned int field_BC;
	unsigned int field_C0;
	unsigned int field_C4;
	unsigned int field_C8;
	unsigned int field_CC;
	unsigned int field_D0;
	unsigned int field_D4;
	unsigned int field_D8;
	unsigned int field_DC;
	unsigned int field_E0;
	unsigned int field_E4;
	unsigned int field_E8;
	unsigned int field_EC;
	unsigned int field_F0;
	unsigned int field_F4;
	unsigned int field_F8;
	unsigned int field_FC;
	unsigned int field_100;
	unsigned int field_104;
	unsigned int field_108;
	unsigned int field_10C;
	unsigned int field_110;
	unsigned int field_114;
	unsigned int field_118;
	unsigned int field_11C;
	unsigned int field_120;
	unsigned int field_124;
	unsigned int field_128;
	unsigned int field_12C;
	unsigned int field_130;
	unsigned int field_134;
	unsigned int field_138;
	unsigned int field_13C;
	unsigned char field_140;
	unsigned char field_141;
	unsigned char field_142;
	unsigned short field_143;
	unsigned short MsgType;
	unsigned char CheckSum;
	unsigned char field_148;
	unsigned char field_149[10000];
};
#pragma pack(pop)

#endif // DAOC_H