#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include <peconv.h>

class ModuleData {

public:
	ModuleData(HANDLE _processHandle, HMODULE _module)
		: processHandle(_processHandle), moduleHandle(_module),
		is_module_named(false), original_size(0), original_module(nullptr),
		is_relocated(false), is_dot_net(false)
	{
		memset(szModName, 0, MAX_PATH);
		loadModuleName();
	}

	ModuleData(HANDLE _processHandle, HMODULE _module, std::string module_name)
		: processHandle(_processHandle), moduleHandle(_module),
		is_module_named(false), original_size(0), original_module(nullptr),
		is_relocated(false), is_dot_net(false)
	{
		memset(szModName, 0, MAX_PATH);
		memcpy(this->szModName, module_name.c_str(), module_name.length());
	}

	~ModuleData()
	{
		peconv::free_pe_buffer(original_module, original_size);
	}

	bool is64bit()
	{
		if (original_module == nullptr) {
			return false;
		}
		return peconv::is64bit(original_module);
	}

	bool isDotNet() { return this->is_dot_net; }

	ULONGLONG rvaToVa(DWORD rva)
	{
		return reinterpret_cast<ULONGLONG>(this->moduleHandle) + rva;
	}

	DWORD vaToRva(ULONGLONG va)
	{
		ULONGLONG module_base = reinterpret_cast<ULONGLONG>(this->moduleHandle);
		if (va < module_base) {
			return NULL; // not this module
		}
		if (va > module_base + this->original_size) {
			return NULL; // not this module
		}
		ULONGLONG diff = (va - module_base);
		return static_cast<DWORD>(diff);
	}

	bool isInitialized()
	{
		return original_module != nullptr;
	}
	
	bool loadOriginal();

	bool switchToWow64Path();
	bool reloadWow64();
	bool relocateToBase(ULONGLONG new_base);

	HANDLE processHandle;
	HMODULE moduleHandle;
	char szModName[MAX_PATH];
	bool is_module_named;

	PBYTE original_module;
	size_t original_size;

protected:
	bool _loadOriginal(bool disableFSredir);
	bool loadModuleName();
	bool isDotNetManagedCode();
	bool is_relocated;
	bool is_dot_net;

	friend class PeSection;
};

// the module loaded within the scanned process
class RemoteModuleData
{
public:

	static std::string getModuleName(HANDLE _processHandle, HMODULE _modBaseAddr);
	static std::string getMappedName(HANDLE _processHandle, LPVOID _modBaseAddr);

	RemoteModuleData(HANDLE _processHandle, HMODULE _modBaseAddr)
		: processHandle(_processHandle), modBaseAddr(_modBaseAddr)
	{
		is_ready = false;
		memset(headerBuffer, 0, peconv::MAX_HEADER_SIZE);
		if (init()) {
			DWORD img_size = peconv::get_image_size(headerBuffer);
			loadRemotePe(img_size);
		}
	}

	virtual ~RemoteModuleData()
	{
		freeRemotePe();
	}

	bool isSectionExecutable(size_t section_number);
	bool hasExecutableSection();
	bool isInitialized()
	{
		if (!is_ready) init();
		return is_ready;
	}

	size_t getModuleSize()
	{
		if (!is_ready) return 0;
		return peconv::get_image_size((const BYTE*) headerBuffer);
	}

	ULONGLONG getRemoteBase()
	{
		if (!is_ready) return 0;
		return peconv::get_image_base((const BYTE*)headerBuffer);
	}

	BYTE headerBuffer[peconv::MAX_HEADER_SIZE];

protected:
	bool loadRemotePe(size_t buf_size)
	{
		freeRemotePe();
		peBuffer = peconv::alloc_pe_buffer(buf_size, PAGE_READWRITE);
		if (!peBuffer) {
			return false;
		}
		peBufferSize = buf_size;
		if (!peconv::read_remote_pe(this->processHandle, (BYTE*)this->modBaseAddr, buf_size, peBuffer, peBufferSize)) {
			return false;
		}
		ULONGLONG found_base = peconv::find_base_candidate(peBuffer, peBufferSize);
		ULONGLONG hdr_base = peconv::get_image_base(peBuffer);
		std::cout << "Found Base: " << std::hex << found_base << " vs Header Base: " << hdr_base << "\n";
		if (found_base != 0 && hdr_base != found_base) {
			std::cout << "Dumping the PE\n";
			peconv::dump_to_file("test.bin", peBuffer, peBufferSize);
			system("pause");
		}
		return true;
	}

	void freeRemotePe()
	{
		if (peBuffer) {
			peconv::free_pe_buffer(peBuffer);
			peBuffer = nullptr;
			peBufferSize = 0;
		}
	}

	bool init();
	bool loadHeader();
	ULONGLONG getRemoteSectionVa(const size_t section_num);

	HANDLE processHandle;
	HMODULE modBaseAddr;

	PBYTE peBuffer;
	size_t peBufferSize;
	bool is_ready;

	friend class PeSection;
};
