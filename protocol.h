#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include "daoc.h"

#define ASK_ENC_KEY 101

#define ERROR_LOGIN 200

#define LOGIN_OK 240

#define Unknow_00	241
#define Unknow_01	242


char ComputeCheckSum(char *buf, int Size);
void AskEncKey(struct InfoCon *info, struct CHPack *pack);
void LoginOk(struct InfoCon *info, struct CHPack *pack);

#endif // PROTOCOL_H_