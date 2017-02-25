// NewSection.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

#include <Windows.h>
#include <iostream>
#include <strsafe.h>

using namespace std;


// �������
typedef struct tag_IATTableContent
{
	IMAGE_THUNK_DATA OriginalThunk[2];
	IMAGE_THUNK_DATA FirstThunk[2];
	IMAGE_IMPORT_BY_NAME ImportByName;
	CHAR szFuncName[64];
	CHAR szDllName[MAX_PATH];
}IATTableContent, *LPIATTableContent;


// ��Щ�ض�����ʵ����Ѿ���windows.h�ж�����ˣ������64λ�Ϳ�����64λPE�ļ���Ⱦ
// �����32λ�����Ⱦ64λ�ļ����Ǿͱ���д��IMAGE_NT_HEADERS64 ������ӣ�
// ��Ϊ����ɵ���32λ����IMAGE_NT_HEADERS�ᱻ�����IMAGE_NT_HEADERS32��
#ifdef _WIN64
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
#else
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
#endif

//32 / 64 ����ʹ�������
#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
	((ULONG_PTR)(ntheader) +                                            \
	FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
	((ntheader))->FileHeader.SizeOfOptionalHeader   \
	))

//����ļ����ڴ�ӳ��
BOOL
MapFileOfSection(HANDLE& hFile,char* szFilePath,ULONG_PTR* ulBaseAddress);

BOOL
ModifyPEImportTableInject(HANDLE hFile,ULONG_PTR ulBaseAddress,char* szDllName);		//Dllͨ������·������Ϊ�������ֻ�ж�̬������ƣ�����ͬһĿ¼�¾Ϳ��ԣ����߷���ϵͳĿ¼�¶���

//�ж�RVA�����ĸ���
PIMAGE_SECTION_HEADER
	GetEnclosingSectionHeader(ULONG_PTR rva,PIMAGE_NT_HEADERS pNTHeader);

//�����ȶ��룬�ڴ����Ȼ������ļ�����
DWORD
	AligmentAddress(DWORD ulRva, DWORD dwAligment);

//�õ�һ���ڵ��ڴ�̧����
ULONG_PTR
	GetSectionMemoryIncrement(PIMAGE_SECTION_HEADER pSection);

// BOOL
// 	CreateVirusFile(HANDLE hSourceFile, ULONG_PTR ulBaseAddress);

//HANDLE g_hFile = NULL;		//�ļ����

int _tmain(int argc, _TCHAR* argv[])
{
	char szFilePath[MAX_PATH] = "D:\\Target.exe";
	char szDllName[MAX_PATH] = "D:\\Dll.dll";

	HANDLE hFile = INVALID_HANDLE_VALUE;
	ULONG_PTR ulBaseAddress = 0;	//PE�ļ����ڴ��л�ַ
	if (!MapFileOfSection(hFile,szFilePath, &ulBaseAddress))
	{
		printf("MapFile Failed\r\n");
		return -1;
	}
	printf("BaseAddress:%p\r\n", ulBaseAddress);

	if (!ModifyPEImportTableInject(hFile,ulBaseAddress, szDllName))
	{
		printf("ModifyPEImportTable Failed\r\n");
		return -1;
	}


	CloseHandle(hFile);

	return 0;
}

BOOL
	MapFileOfSection(HANDLE& hFile,char* szFilePath, ULONG_PTR* ulBaseAddress)
{
	hFile = CreateFileA(
		szFilePath,   //�ļ���  
		GENERIC_READ | GENERIC_WRITE, //���ļ����ж�д����  
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,  //���Ѵ����ļ�  
		FILE_ATTRIBUTE_NORMAL,
		0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Not exsit\r\n");
		return FALSE;
	}
	//����ֵsize_high,size_low�ֱ��ʾ�ļ���С�ĸ�32λ/��32λ  
	DWORD size_low, size_high;
	size_low = GetFileSize(hFile, &size_high);

	//�����ļ����ڴ�ӳ���ļ���     
	HANDLE hMapFile = CreateFileMapping(
		hFile,
		NULL,
		PAGE_READWRITE | SEC_COMMIT,  //��ӳ���ļ����ж�д  
		0,
		0,			  //������������64λ������֧�ֵ�����ļ�����Ϊ16EB .������������4KB�ڴ棬Ϊ��д���µĵ�����������������һ�������������������0�Ϳ��ԡ�
		NULL);

	if (hMapFile == INVALID_HANDLE_VALUE)
	{
		printf("Can't create file mapping.Error%d:/n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	//���ļ�����ӳ�䵽���̵ĵ�ַ�ռ�  
	void* pvFile = MapViewOfFile(
		hMapFile,
		FILE_MAP_READ | FILE_MAP_WRITE,
		0,
		0,
		0);

	if (pvFile == NULL)
	{
		CloseHandle(hFile);
		CloseHandle(hMapFile);
		return FALSE;
	}

	*ulBaseAddress = (ULONG_PTR)pvFile;
	return TRUE;
}

BOOL
	ModifyPEImportTableInject(HANDLE hFile,ULONG_PTR ulBaseAddress, char* szDllName)
{
	DWORD dwWriteSize = 0;
	DWORD dwReturnSize = 0;
	DWORD dwRet = 0;
	PVOID pWriteBuffer = NULL;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ulBaseAddress;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	//��λ�����һ���ڵĽ���Ϊֹ����������ӵ��Ǹ���������Ǹ��ڱ�Ϊ���ǳ�ʼ���½ڵ�VirtualAddress�Լ�PointerToRawData��������룩
	PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)(section + pNTHeader->FileHeader.NumberOfSections - 1);

	//�������ļ�����Ȼ���Ը��ǵ�Դ�ļ�����޸��ļ��ļ���
	HANDLE hTargetFile = CreateFileA("D:\\calcVirus.exe", FILE_ALL_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hTargetFile == INVALID_HANDLE_VALUE)
	{
		int a = GetLastError();
		printf("Create Virus Failed\r\n");
		return FALSE;
	}

	//д��Dos Header
	dwRet = WriteFile(hTargetFile, pDosHeader, sizeof(IMAGE_DOS_HEADER), &dwReturnSize, NULL);
	if (!dwRet)
	{
		printf("Write Virus DosHeader Failed\r\n");
		return FALSE;
	}

	//д��Dos Stub
	dwWriteSize = pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	dwRet = WriteFile(hTargetFile, (LPVOID)((DWORD)pDosHeader + sizeof(IMAGE_DOS_HEADER)), dwWriteSize, &dwReturnSize, NULL);
	if (!dwRet)
	{
		printf("Write Virus DosStub Failed\r\n");
		return FALSE;
	}

	//д��Nt Header
	dwWriteSize = sizeof(IMAGE_NT_HEADERS);
	dwRet = WriteFile(hTargetFile, pNTHeader, dwWriteSize, &dwReturnSize, NULL);
	if (!dwRet)
	{
		printf("Write Virus NtHeader Failed\r\n");
		return FALSE;
	}

	//Original Section Table + New Section + 0(������־)��û��0���Ա���
	//pNTHeader->FileHeader.NumberOfSections û�а�0���������־�����ڣ�����Ҫ��2
	DWORD dwSectionSize = (pNTHeader->FileHeader.NumberOfSections + 2)*sizeof(IMAGE_SECTION_HEADER);
	PIMAGE_SECTION_HEADER pUpdatedSection = (PIMAGE_SECTION_HEADER)new char[dwSectionSize];
	memset(pUpdatedSection, 0, dwSectionSize);
	CopyMemory(pUpdatedSection, section, sizeof(IMAGE_SECTION_HEADER)*pNTHeader->FileHeader.NumberOfSections);

	//����½�
	PIMAGE_SECTION_HEADER pNewSection = pUpdatedSection + pNTHeader->FileHeader.NumberOfSections;
	//ȡ�ڴ����ȣ��ļ�����
	DWORD dwFileAlignment = pNTHeader->OptionalHeader.FileAlignment;
	DWORD dwMemAlignment = pNTHeader->OptionalHeader.SectionAlignment;

	//New Section�����滹��һ���ڣ���ֹ�������ݵ��ڴ棬��ʼ��һ��
	memset(pNewSection, 0, 2 * sizeof(IMAGE_SECTION_HEADER));

	char szNewSectionName[] = ".Crake";
	StringCchCopyA((char*)(pNewSection->Name), 12, szNewSectionName);

	pNewSection->PointerToRelocations = 0;
	pNewSection->PointerToLinenumbers = 0;
	pNewSection->NumberOfRelocations = 0;
	pNewSection->NumberOfLinenumbers = 0;
	pNewSection->Characteristics = 0xE0000040;	//����ڵķ������ԣ�0xE0000040��ʾ���ɶ���д��ִ�У�����δ��ʼ�������ݡ������������ı�־λ��90%������⡣
	pNewSection->VirtualAddress = AligmentAddress(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, dwMemAlignment);
	pNewSection->PointerToRawData = AligmentAddress(pLastSection->PointerToRawData + pLastSection->SizeOfRawData, dwFileAlignment);

	//����հ��������д��ڱ�����ɽڱ���ļ�ƫ�ƣ���ô��Ҫ��ԭ�ȵĽڱ������һ������
	//��һ���ڱ��ƫ�Ƹ� PE�ļ�ͷ����Dos + DosStub + NtHeader + SectionHeader����С���Ƚ�
	DWORD dwMiniPointer = 0;
	DWORD dwSizeDelta = 0;
	BOOL  bNeedModify = FALSE;
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		if (pUpdatedSection[i].Name)
		{
			if (0 == dwMiniPointer)
				dwMiniPointer = (DWORD)(pUpdatedSection[i].PointerToRawData);
			if ((pUpdatedSection[i].PointerToRawData) < dwMiniPointer)
				dwMiniPointer = (DWORD)pUpdatedSection[i].PointerToRawData;
		}
	}

	//д���ļ���PEͷ�����ܴ�С�����ܻ����ȫ���ڱ���ļ�ƫ�Ƶ�̧��
	//������������ڵ�һ���ڵ��ļ�ƫ�� С�� ��д��PEͷ�����ܴ�С ��ʱ��
	//��������ˣ�����Ҳ�ܼ򵥣�����һЩ�հ������������ļ����ȣ����б�����Ҫ���½ڱ���ļ�ƫ��
	//ֵ��ע����ǣ����ļ��Ĳ��������ϲ��õ�VirtualAddress��ֻ�������ַ��ʱ����õ�RVA
	DWORD dwTmp = (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + dwSectionSize);

	//д���PEͷ��Ԥ�Ʒ�Χ�ھͲ���Ҫ�Խڱ���ļ�ƫ�ƽ�������
	if (dwMiniPointer >= dwTmp)
		dwSizeDelta = dwMiniPointer - dwTmp;
	//д���PEͷ������Ԥ�Ʒ�Χ�ھ���Ҫ�Խڱ���ļ�ƫ�ƽ�������
	else
	{
		// ����˵���ļ�����20��д���PEͷ���ܴ�С25�����ʱ�򳬳���Ԥ�Ʒ�Χ��Ҫ�����������������ȵ�ԭ�򣬺���Ҫ����һ���ֽڣ�������� 20 - 25 % 20 = 15 ----> 25+15 = 40
		// ����������������Ͳ����κδ��������� PEͷ���ܴ�СΪ40���ļ�����20.
		dwSizeDelta = dwTmp % (pNTHeader->OptionalHeader.FileAlignment);
		if (dwSizeDelta != 0)
			dwSizeDelta = pNTHeader->OptionalHeader.FileAlignment - dwSizeDelta;
		else dwSizeDelta = 0;

		//ָʾÿ���ڱ���ļ�ƫ����Ҫ���¼���
		bNeedModify = TRUE;
	}

	BYTE* pDelta = new BYTE[dwSizeDelta];
	memset(pDelta, 0, dwSizeDelta);
	dwMiniPointer = dwTmp;
	dwMiniPointer += dwSizeDelta;

	if (bNeedModify)
	{
		for (int i = 0; i < (UINT)(pNTHeader->FileHeader.NumberOfSections + 1); i++)
		{
			if (0 != i)
				pUpdatedSection[i].PointerToRawData =
				pUpdatedSection[i - 1].PointerToRawData +
				pUpdatedSection[i - 1].SizeOfRawData;
			else
				pUpdatedSection[i].PointerToRawData = dwMiniPointer;
		}
	}

	//д��ڱ� ��Original + New + 0��
	WriteFile(hTargetFile, pUpdatedSection, dwSectionSize, &dwReturnSize, NULL);
	//д��հ����� �������ļ����ȣ�
	WriteFile(hTargetFile, pDelta, dwSizeDelta, &dwReturnSize, NULL);

	//д��������
	for (int i = 0; i < (UINT)(pNTHeader->FileHeader.NumberOfSections); i++)
	{
		//SizeOfRawData �ļ��ǰ������ֵ����� VirtualSize��������ʵ��С�����һ��Ҫ���
		//�������ڴ�ӳ��PE֮�������ڵĴ�СҲ��SizeOfRawData������ʵ�������ݵĴ�С��VirtualSize���˴������һ��Ҫͣ��
		WriteFile(hTargetFile, (LPVOID)(ulBaseAddress + section[i].PointerToRawData), section[i].SizeOfRawData, &dwReturnSize, NULL);
	}

	// Copy Import_Table to NewSection
	PIMAGE_IMPORT_DESCRIPTOR  pImportDesc = 0;
	PIMAGE_SECTION_HEADER     pSection = 0;
	PIMAGE_THUNK_DATA         pThunk, pThunkIAT = 0;
	ULONG_PTR				  Offset = -1;

	//��õ�������ڵĽڶ�Ӧ�Ľڱ�
	pSection = GetEnclosingSectionHeader(
		pNTHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		pNTHeader);

	if (!pSection)
	{
		fprintf(stderr, "No Import Table../n");
		return -1;
	}

	//��ǰ�ڵ��ڴ�̧��ֵ��ע��ÿ���ڵ��ڴ�̧��ֵ���ܲ�һ���������ڲ��������ڵ�ʱ�򣬴�ֵ��Ҫ���¡�
	Offset = GetSectionMemoryIncrement(pSection);	

	pImportDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)(pNTHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - Offset + ulBaseAddress);

	// ȡ�������DLL�ĸ���
	int nImportDllCount = 0;
	while (1)
	{
		if ((pImportDesc->TimeDateStamp == 0) && (pImportDesc->Name == 0))
			break;
		pThunk = (PIMAGE_THUNK_DATA)(pImportDesc->Characteristics);
		pThunkIAT = (PIMAGE_THUNK_DATA)(pImportDesc->FirstThunk);

		if (pThunk == 0 && pThunkIAT == 0)
			return -1;

		nImportDllCount++;
		pImportDesc++;
	}

	// �ָ�pImportDesc��ֵ,��������ĸ��Ƶ�ǰ�����Ĳ���.
	pImportDesc -= nImportDllCount;

	//һ�����������20�ֽڣ�����һ���½ṹ���һ��0�����ṹ�塣����Ҫд���ļ��ĵ����Ĵ�С
	DWORD dwEndOfRawDataAddr = pNewSection->VirtualAddress;
	DWORD dwIATDESCSize = (nImportDllCount + 2) * 20;	

	PIMAGE_IMPORT_DESCRIPTOR pImportDescVector =
		(PIMAGE_IMPORT_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwIATDESCSize);
	if (pImportDescVector == NULL)
	{
		printf("HeapAlloc() failed. --err: %d/n", GetLastError());
		return -1;
	}
	memset(pImportDescVector, 0, dwIATDESCSize);
	CopyMemory(pImportDescVector + 1, pImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR) * (nImportDllCount + 1));	//New + Original[nImportDllCount] + 0;

	//ÿ�������ڵ��ڴ��ļ�ƫ�ƿ��ܲ�һ��
	Offset = GetSectionMemoryIncrement(pNewSection);		

	//�����±���Ҫ�õ���������
	//ע��һ�£�PE32��PE64�����Ĳ�֮ͬ����������IMAGE_THUNK_DATA����ṹ������ṹʵ����ֻ����һ��4/8�ֽڵ�ƫ�ƣ��ǹ����壩
	IATTableContent iatTableContent = {0};
	iatTableContent.FirstThunk[0].u1.AddressOfData = offsetof(IATTableContent, ImportByName);
	iatTableContent.OriginalThunk[0].u1.AddressOfData = offsetof(IATTableContent, ImportByName);

	StringCchCopyA(iatTableContent.szDllName, MAX_PATH, szDllName);
	StringCchCopyA((char*)(iatTableContent.ImportByName.Name), 64, "HelloShine");	//Dll��дһ�������Ƶ����ĵ������������û�е�������������Ӧ���ǻ����ġ�
	iatTableContent.ImportByName.Hint = 0;

	pImportDescVector->FirstThunk = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, FirstThunk);
	pImportDescVector->OriginalFirstThunk = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, OriginalThunk);
	pImportDescVector->Name = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, szDllName);
	pImportDescVector->TimeDateStamp = -1;	//ʱ��������飬��Ҫ����԰������ġ�
	pImportDescVector->ForwarderChain = -1;	//ת��ֵ�����飬�˽����ֵ�Ǹ�ʲô�ġ�

	iatTableContent.FirstThunk[0].u1.AddressOfData = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, ImportByName);
	iatTableContent.OriginalThunk[0].u1.AddressOfData = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, ImportByName);


	// ���½���д���µĵ��������
	DWORD dwRetSize = 0;
	DWORD lDistanceToMove = pNewSection->PointerToRawData;

	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, pImportDescVector, dwIATDESCSize, &dwRetSize, NULL);
	WriteFile(hTargetFile, &iatTableContent, sizeof(IATTableContent), &dwRetSize, NULL);

	DWORD dwBytesWritten = 0;
	DWORD dwBuffer = pNewSection->VirtualAddress;


	// �޸�IMAGE_DIRECTOR_ENTRY_IMPORT��VirtualAddress�ĵ�ַ,
	// ʹ��ָ���µĵ�����λ��
	int nRet = 0;
	lDistanceToMove = (long)&(pNTHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) - ulBaseAddress;

	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);

	printf("OrigEntryImport: %x\r\n", pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	nRet = WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);
	if (!nRet)
	{
		printf("WriteFile(ENTRY_IMPORT) failed. --err: %d\r\n", GetLastError());
		return FALSE;
	}
	printf("NewEntryImport: %x\r\n", dwBuffer);

	// �޸ĵ������
	nRet = WriteFile(hTargetFile, (PVOID)&dwIATDESCSize, 4, &dwBytesWritten, NULL);
	if (!nRet)
	{
		printf("WriteFile(Entry_import.size) failed. --err: %d\n", GetLastError());
		return FALSE;
	}


	pNewSection = section + pNTHeader->FileHeader.NumberOfSections;

	//PEһЩֵ��Ҫ��������Щֵ�����������е�ʱ��ᱨ��������Ч��win32���򡱣����Գ��Կ���Ч����
	//PE�ļ���С����
	lDistanceToMove = (ULONG_PTR)(&(pNTHeader->OptionalHeader.SizeOfImage)) - ulBaseAddress;
	dwBuffer = pNTHeader->OptionalHeader.SizeOfImage + 0x1000;
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//PE�ڴ�С����
	lDistanceToMove = (ULONG_PTR)(&(pNTHeader->FileHeader.NumberOfSections)) - ulBaseAddress;
	dwBuffer = pNTHeader->FileHeader.NumberOfSections + 1;
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//PEͷ��С����
	lDistanceToMove = (ULONG_PTR)(&(pNTHeader->OptionalHeader.SizeOfHeaders)) - ulBaseAddress;
	dwBuffer = pNTHeader->OptionalHeader.SizeOfHeaders + 2*sizeof(IMAGE_SECTION_HEADER);
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//�½�ʵ�ʴ�С����
	lDistanceToMove = (ULONG_PTR)(&(pNewSection->Misc.VirtualSize)) - ulBaseAddress;
	dwBuffer = dwIATDESCSize + sizeof(IATTableContent);
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//�½����ȴ�С���죬���������һ�����ˣ�����Ҳû����0������ɶ��룬�������ֵ�͸�ʵ�ʴ�Сһ���ˡ����ԸĽ���
	lDistanceToMove = (ULONG_PTR)(&(pNewSection->SizeOfRawData)) - ulBaseAddress;
	dwBuffer = dwIATDESCSize + sizeof(IATTableContent);
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//��󣬶��ںܶ�ϵͳ�ļ�����ʲôcalc.exe notepad.exe���ڰ������
	//��Щ���ݴ�����PE�ļ�ͷ֮�󣬵�һ����֮ǰ���Ƕοհ�����������д�����ļ���ʱ��û��д���ⲿ�ֵ����ݣ��ǰ�0����
	//��ˣ��������Ҫ����������RVA��Size�ó�0������һ������Լ���vs�����exe�������������ġ�

	lDistanceToMove = (ULONG_PTR)(&(pNTHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress)) - ulBaseAddress;
	ULONG64 uZeroEightBit = 0;
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&uZeroEightBit, 8, &dwBytesWritten, NULL);

	//�ͷ��ڴ棬��ɲ�����������֮ǰ���ļ�ӳ�䶼��û�ͷš�
	HeapFree(GetProcessHeap(), 0, pImportDescVector);
	CloseHandle(hTargetFile);

	return TRUE;
}


//
// Copy from Matt Pietrek
// Given an RVA, look up the section header that encloses it and return a
// pointer to its IMAGE_SECTION_HEADER
//
PIMAGE_SECTION_HEADER
	GetEnclosingSectionHeader(
	ULONG_PTR rva,
	PIMAGE_NT_HEADERS pNTHeader
	)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	unsigned i;

	for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
	{
		// Is the RVA within this section?
		if ((rva >= section->VirtualAddress) &&
			(rva < (section->VirtualAddress + section->Misc.VirtualSize)))
			return section;
	}

	return 0;
}


//ע��������������ulRva������dwAligment�ı�����ʱ�򣬻᷵�����������1��dwAligment��С
//���ԣ�����ط�Ҫ��Ҫ�ж��ǲ������ı��������˶��졣
DWORD
	AligmentAddress(DWORD ulRva, DWORD dwAligment)
{
	if (ulRva % dwAligment == 0)
		return ulRva;
	else
		return (ulRva / dwAligment + 1)*dwAligment;
}

ULONG_PTR
	GetSectionMemoryIncrement(PIMAGE_SECTION_HEADER pSection)
{
	if (!pSection)
		return NULL;
	else
		return (pSection->VirtualAddress - pSection->PointerToRawData);
}