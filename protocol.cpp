#include "protocol.h"

char ComputeCheckSum(char *buf, int Size)
{
  char result;
  int i;

  result = 0;
  for (i = 0; i < Size; ++i)
    result += buf[i];
  return result;
}

void AskEncKey(struct InfoCon *info, struct CHPack *pack)
{
	unsigned short Version;
	unsigned short unk;

	GetWordInPacket(pack, &Version);
	printf("Version Packet : %X\n", Version);
	GetWordInPacket(pack, &unk);

	SendEncKey(info);
	printf("[+] Encryption key sent\n");
	info->sym_keyset = 1;
	info->sequence += 1;
	SendClientInfo(info);
	printf("[+] Client info sent\n");
}

void LoginOk(struct InfoCon *info, struct CHPack *pack)
{
	unsigned int a;
	unsigned int b;

	GetDWORDInPacket(pack, &a);
	GetDWORDInPacket(pack, &b);
	printf("a = %X ; b = %X\n", a, b);
}