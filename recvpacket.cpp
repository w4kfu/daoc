#include "recvpacket.h"

void GetWordInPacket(struct CHPack *pack, unsigned short *val)
{
  *val = (unsigned short)ROL16(*(unsigned short *)&pack->buf[pack->pos], 8);
  pack->pos += 2;
  if (pack->pos > pack->PacketSize)
  {
	  printf("[-] WORD Overrun\n");
	  exit(EXIT_FAILURE);
  }
}

void GetCharInPacket(struct CHPack *pack, char *val)
{
  *val = pack->buf[pack->pos];
  if (pack->pos > pack->PacketSize)
  {
	  printf("[-] char Overrun\n");
	  exit(EXIT_FAILURE);
  }
}

void GetStringInPacket(struct CHPack *pack, char *val, unsigned int MaxSize)
{
	char *v3;
	int v4;
	int result;

	v3 = val;
	*val = 0;
	GetWordInPacket(pack, (unsigned __int16 *)&val);
	v4 = (unsigned __int16)val;
	if ( MaxSize > (unsigned __int16)val )
	{
		memcpy(v3, &pack->buf[pack->pos], (unsigned __int16)val);
		pack->pos += v4;
		v3[v4] = 0;
		result = pack->pos;
		if (result > pack->PacketSize)
		{	
			printf("[-] String Overrun\n");
			exit(EXIT_FAILURE);
		}	
	}
	else
	{
		printf("[-] String size error\n");
		exit(EXIT_FAILURE);
	}
}

void GetDWORDInPacket(struct CHPack *packet, unsigned int *a2)
{
	int v2;
	int v3;
	int result;
	
	v2 = *(DWORD*)&packet->buf[packet->pos];
	v3 = v2;
	*a2 = (((v2 << 16) | *(DWORD*)&packet->buf[packet->pos] & 0xFF00) << 8) | (((*(DWORD*)&packet->buf[packet->pos] >> 16) | v3 & 0xFF0000u) >> 8);
	packet->pos += 4;
	result = packet->pos;
	if (result > packet->PacketSize)
	{
		printf("[-] DWORD Overrun\n");
		exit(EXIT_FAILURE);	
	}
}

void ParsePacket(struct InfoCon *info, struct Packet *packet)
{
	CHPack hpack = {0};

	if (packet->LengthPacket < 8 || packet->LengthPacket > 0x7D08)
	{
		printf("[-] WTF with this size of packet\n");
		exit(EXIT_FAILURE);
	}

	hpack.PacketSize = packet->LengthPacket - 8;

	if (info->sym_keyset == 1)
	{
		rc4_read((unsigned char*)&packet->MsgType, packet->LengthPacket - 4, info->sym_sbox);
		printf("[+] Received following packet : <Encrypted : TRUE> <Size : %X>\n", packet->LengthPacket - 4);
		hex_dump(&packet->MsgType, packet->LengthPacket - 4);
	}
	else
	{
		printf("[+] Received following packet : <Encrypted : FALSE> <Size : %X>\n", packet->LengthPacket - 4);
		hex_dump(&packet->MsgType, packet->LengthPacket - 4);
	}


	hpack.MsgType = (unsigned short)ROL16(packet->MsgType, 8);

	// COMPUTE CRC
	if (info->sym_keyset == 1)
	{
		char CRC;
		char ComputedCRC;

		CRC = packet->CheckSum;
		hpack.CheckSum = packet->CheckSum;
		ComputedCRC = (unsigned __int8)ComputeCheckSum((char*)&packet->field_149, hpack.PacketSize);
		if (ComputedCRC != CRC)
		{
			printf("Packet checksum for packet type %d is bad, expected %d got %d", CRC, ComputedCRC);
			exit(EXIT_FAILURE);
		}
	}

	memcpy(hpack.buf, &packet->field_149, hpack.PacketSize);

	HandlePacket(info, &hpack);
}

void HandlePacket(struct InfoCon *info, struct CHPack *pack)
{
	char OtherCase;

	printf("[+] Message Type: %d, pkt size:%d\n", pack->MsgType, pack->PacketSize);
	switch (pack->MsgType)
	{
	case ASK_ENC_KEY:
		printf("[+] Server asking for encryption key\n");
		AskEncKey(info, pack);
		break;
	case ERROR_LOGIN:
		printf("[-] Error login\n");
		GetCharInPacket(pack, &OtherCase);
		printf("Other Case : %X\n", OtherCase);
		//ErrorLogin(info, pack);
		break;
	case LOGIN_OK:
		printf("[+] Login OK\n");
		LoginOk(info, pack);
		break;
	case Unknow_00:
		break;
	case Unknow_01:
		break;
	default:
		printf("[-] Unhandled packet !!!\n");
	}

}