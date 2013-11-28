#include "sendpacket.h"

void SendClientInfo(struct InfoCon *info)
{
	CHPack hpack = {0};

	hpack.field_0 = 0;
	hpack.pos = 0;
	hpack.PacketSize = 0;
	hpack.CheckSum = 0;
	hpack.MsgType = 300;

	// username
	MemcpyInPacket(&hpack, ACCOUNT_NAME, strlen(ACCOUNT_NAME));
	// password
	MemcpyInPacket(&hpack, ACCOUNT_PASSWORD, strlen(ACCOUNT_PASSWORD));

	SetWordInPacket(&hpack, 0x09);
	hpack.pos += 1;
	SendPacket(info, &hpack);
}

void SendEncKey(struct InfoCon *info)
{
	CHPack hpack = {0};
	char key[60] = {0};
	int i;
	char Output[8096];
	unsigned long OutputSize;

	OutputSize = 8096;
	hpack.field_0 = 0;
	hpack.pos = 0;
	hpack.PacketSize = 0;
	hpack.CheckSum = 0;
	hpack.MsgType = 340;
	i = 0;
	do
	  key[i++] = rand();
	while (i < 59);
	SetWordInPacket(&hpack, 59);
	MemcpyInPacket(&hpack, key, 59);

	prepare_rsa((unsigned char*)hpack.buf, hpack.pos, (unsigned char*)Output, &OutputSize);

	memcpy(hpack.buf, Output, OutputSize);
	hpack.pos = OutputSize;
	SendPacket(info, &hpack);

	setup_sbox_from_key(key, 59, info->sym_sbox);
}

void SetWordInPacket(CHPack *packet, unsigned short val)
{
  if (packet->pos + 2 >= 32000)
  {
	  printf("[-] WORD Overrun\n");
	  exit(EXIT_FAILURE);
  }
  else
  {
    *(unsigned short *)&packet->buf[packet->pos] = (unsigned short)ROL16(val, 8);
    packet->pos += 2;
  }
}

int MemcpyInPacket(CHPack *packet, char *Buffer, int Size)
{
  int result; // eax@2
  int v4; // eax@4

  if (Buffer)
  {
    if (packet->pos + 2 >= 32000)
    {
	  printf("[-] Pack length of block Overrun\n");
	  exit(EXIT_FAILURE);
    }
    else
    {
      SetWordInPacket(packet, Size);
      v4 = packet->pos;
      if ( (unsigned int)(v4 + Size) >= 0x7D00 )
      {
		printf("[-] Pack block Overrun\n");
		exit(EXIT_FAILURE);
      }
      else
      {
        memcpy(&packet->buf[v4], Buffer, Size);
        packet->pos += Size;
      }
    }
  }
  else
  {
    SetWordInPacket(packet, 0);
  }
}

int SendPacket(struct InfoCon *infocon, struct CHPack *packet)
{
	struct PacketSend packsend;
	int res;

	memset(&packsend, 0, sizeof (struct PacketSend));

	packsend.version = 6939;								// Setup Version
	packsend.size = (unsigned short)ROL16((unsigned short)(packet->pos) + 4, 8);	// Setup Size

	packsend.type = (packet->MsgType >> 8) | ((packet->MsgType & 0xFF) << 8);

	if (infocon->sym_keyset == 1)
	{
		packsend.checksum = ComputeCheckSum(packet->buf, packet->pos);				// Setup CheckSum
		packsend.seq = infocon->sequence;											// Setup Sequence
	}
	memcpy(packsend.buf, packet->buf, packet->pos);
	packet->PacketSize = packet->pos;
	hex_dump(&packsend, packet->PacketSize + 8);
	if (infocon->sym_keyset == 1)
	{
		rc4_write((unsigned char*)&packsend.type, packet->PacketSize + 4, infocon->sym_sbox);
	}
	printf("[+] Sending following packet : (Encrypted : %s)\n", infocon->sym_keyset ? "TRUE" : "FALSE");
	hex_dump(&packsend, packet->PacketSize + 8);
	res = send(infocon->sock, (const char *)&packsend, packet->PacketSize + 8, 0);
	if (res != -1)
		return res;
	printf("[-] recv() failed : %d\n" , WSAGetLastError());
	exit(EXIT_FAILURE);
}