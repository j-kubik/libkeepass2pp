/*Copyright (C) 2016 Jaroslaw Kubik
 *
   This file is part of libkeepass2pp library.

libkeepass2pp is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libkeepass2pp is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libkeepass2pp.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <Rpc.h>
#include <winnt.h>

#include <stdexcept>
#include <cassert>
#include <memory>

#include "../include/libkeepass2pp/keepass2pp_config.h"
#include "../include/libkeepass2pp/platform.h"
#include "../include/libkeepass2pp/util.h"


static const uint64_t t1970 = 0x19db1ded53e8000;

std::time_t formatTime( const char* description){
  	struct TimeStruct{
		uint8_t year[4];
		uint8_t separator1;
		uint8_t month[2];
		uint8_t separator2;
		uint8_t day[2];
		uint8_t T;
		uint8_t hour[2];
		uint8_t separator3;
		uint8_t minute[2];
		uint8_t separator4;
		uint8_t second[2];
		uint8_t Z;
		uint8_t end;
	};
	
	const TimeStruct* timeStruct = reinterpret_cast<const TimeStruct*>(description);

	SYSTEMTIME systime;

	systime.wYear = toUIntDate(timeStruct->year);
	if (timeStruct->separator1 != '-') throw std::runtime_error("Bad date format.");
	systime.wMonth = toUIntDate(timeStruct->month);
	if (timeStruct->separator2 != '-') throw std::runtime_error("Bad date format.");
	systime.wDay = toUIntDate(timeStruct->day);
	if (timeStruct->T != 'T') throw std::runtime_error("Bad date format.");
	systime.wHour = toUIntDate(timeStruct->hour);
	if (timeStruct->separator3 != ':') throw std::runtime_error("Bad date format.");
	systime.wMinute = toUIntDate(timeStruct->minute);
	if (timeStruct->separator4 != ':') throw std::runtime_error("Bad date format.");
	systime.wSecond = toUIntDate(timeStruct->second);
	if (timeStruct->Z != 'Z') throw std::runtime_error("Bad date format.");
	if (timeStruct->end != 0) throw std::runtime_error("Bad date format.");
	systime.wMilliseconds = 0;
	systime.wDayOfWeek = 0;

	FILETIME ftime;
	if (SystemTimeToIFileTime(&systime, &ftime) == 0)
		throw std::runtime_error("Bad date format.");

	uint64_t result = (uint64_t(ftime.dwHighDateTime) << 32) | ftime.dwLowDateTime;
	return (result - t1970)/1e7;
}

//------------------------------------------------------------------------------

void SafeAllocator<void>::zero(void* ptr, std::size_t size) noexcept{
	SecureZeroMemory(ptr, size);
}

template class SafeAllocator<void>;

//-----------------------------------------------------------------------------------------------------

signed int Uuid::compare(const Uuid& uuid) const noexcept{
	RPC_STATUS status;
	signed int result = UuidCompare(const_cast<GUID*>(&fuid), const_cast<GUID*>(&uuid.fuid), &status);
	assert(status == RPC_S_OK);
	return result;
}


Uuid::Uuid(const std::vector<uint8_t>& data){
	if (data.size() != 16)
		throw std::range_error("UUID of wrong size.");

	fuid.Data1 = fromLittleEndian<uint32_t>(data.data());
	fuid.Data2 = fromLittleEndian<uint16_t>(data.data() + 4);
	fuid.Data3 = fromLittleEndian<uint16_t>(data.data() + 6);
	std::copy(data.begin() + 8, data.end(), &fuid.Data4[0]);
}

Uuid::Uuid(const std::string& data){
	if (UuidFromStringA(reinterpret_cast<RPC_CSTR>(const_cast<char*>(data.c_str())), &fuid) == RPC_S_INVALID_STRING_UUID)
		throw std::runtime_error("Invalid UUID.");
}

Uuid::Uuid(const std::wstring& data){
	if (UuidFromStringW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(data.c_str())), &fuid) == RPC_S_INVALID_STRING_UUID)
		throw std::runtime_error("Invalid UUID.");
}

namespace{

class RPCDeleter{
public:
	void operator()(RPC_CSTR str){
		RpcStringFreeA(&str);
	}

	void operator()(RPC_WSTR str){
		RpcStringFreeW(&str);
	}


};

}

Uuid::operator std::string() const{
	RPC_CSTR str;
	RPC_STATUS status = UuidToStringA(&fuid, &str);
	if (status == RPC_S_OUT_OF_MEMORY) throw std::bad_alloc();
	std::unique_ptr<typename std::remove_pointer<RPC_CSTR>::type> strsafe(str);
	return std::string(reinterpret_cast<const char*>(str));
}

Uuid::operator std::wstring() const{
	RPC_WSTR str;
	RPC_STATUS status = UuidToStringW(&fuid, &str);
	if (status == RPC_S_OUT_OF_MEMORY) throw std::bad_alloc();
	std::unique_ptr<typename std::remove_pointer<RPC_WSTR>::type> strsafe(str);
	return std::wstring(reinterpret_cast<const wchar_t*>(str));
}

Uuid Uuid::nil() noexcept{
	Uuid result;
	UuidCreateNil(&result.fuid);
	return result;
}

Uuid Uuid::generate() noexcept{
	Uuid result;
	RPC_STATUS status = UuidCreate(&result.fuid);
	assert (status == RPC_S_OK || status == RPC_S_UUID_LOCAL_ONLY );
	unused(status);
	return result;
}

//-------------------------------------------------------------------------------------------------------

void ProtectedBuffer::encrypt(uint8_t* data, std::size_t size){
	if (CryptProtectMemory(data, size, CRYPTPROTECTMEMORY_SAME_PROCESS) == FALSE){
		throw std::runtime_error("Error encrypting memory."); //ToDo: error description?
	}
}

void ProtectedBuffer::decrypt(uint8_t* data, std::size_t size){
	if (CryptUnprotectMemory(data, size, CRYPTPROTECTMEMORY_SAME_PROCESS) == FALSE){
		throw std::runtime_error("Error decrypting memory."); //ToDo: error description?
	}
}


ProtectedBuffer::ProtectedBuffer(SafeString<char> plaintext){
	int paddedSize = (plaintext.size() / CRYPTPROTECTMEMORY_BLOCK_SIZE + 1)*CRYPTPROTECTMEMORY_BLOCK_SIZE;
	plaintext.reserve(paddedSize);
	char fill = paddedSize - plaintext.size();
	for (int i=fill; i>0; i--){
		plaintext.push_back(fill);
	}
	assert(plaintext.size() % CRYPTPROTECTMEMORY_BLOCK_SIZE == 0);

	encrypt(reinterpret_cast<uint8_t*>(&plaintext[0]), plaintext.size());
	data.reserve(paddedSize);
	std::copy(plaintext.begin(), plaintext.end(), back_inserter(data));
}


ProtectedBuffer::ProtectedBuffer(SafeVector<uint8_t> plaintext){
	int paddedSize = (plaintext.size() / CRYPTPROTECTMEMORY_BLOCK_SIZE + 1)*CRYPTPROTECTMEMORY_BLOCK_SIZE;
	plaintext.reserve(paddedSize);
	uint8_t fill = paddedSize - plaintext.size();
	for (int i=fill; i>0; i--){
		plaintext.push_back(fill);
	}
	assert(plaintext.size() % CRYPTPROTECTMEMORY_BLOCK_SIZE == 0);

	encrypt(plaintext.data(), plaintext.size());
	data.reserve(paddedSize);
	std::copy(plaintext.begin(), plaintext.end(), back_inserter(data));

}

SafeString<char> ProtectedBuffer::toString(){

	SafeString<char> result(data.begin(), data.end());
	if (data.size() == 0) return result;

	assert(result.size() % CRYPTPROTECTMEMORY_BLOCK_SIZE == 0);
	decrypt(reinterpret_cast<uint8_t*>(&result[0]), result.size());
	char fill = result.back();
	assert(fill <= CRYPTPROTECTMEMORY_BLOCK_SIZE && fill > 0);
	result.resize(result.size() - fill);
	return result;
}

SafeVector<uint8_t> ProtectedBuffer::toBuffer(){

	SafeVector<uint8_t> result(data.begin(), data.end());
	if (data.size() == 0) return result;

	assert(result.size() % CRYPTPROTECTMEMORY_BLOCK_SIZE == 0);
	decrypt(reinterpret_cast<uint8_t*>(&result[0]), result.size());
	char fill = result.back();
	assert(fill <= CRYPTPROTECTMEMORY_BLOCK_SIZE && fill > 0);
	result.resize(result.size() - fill);
	return result;
}

//------------------------------------------------------------------------------------------------------------

int IFile::readRaw(void* buffer, std::size_t bytes){
	assert(fhandle != INVALID_HANDLE_VALUE);

	DWORD bytesRead;
	if (ReadFile(fhandle, buffer, bytes, &bytesRead, 0) == 0){
		throw std::system_error(system_error_code(GetLastError()));
	}
	return bytesRead;
}


std::wstring IFile::convertName(std::string filename){
	int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, filename.c_str(), filename.size()+1, 0, 0);
	if (size == 0) throw std::system_error(system_error_code(GetLastError()));
	std::vector<wchar_t> resultBuffer(size);
	size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, filename.c_str(), filename.size()+1, resultBuffer.data(), resultBuffer.size());
	if (size == 0) throw std::system_error(system_error_code(GetLastError()));
	return std::wstring(resultBuffer.begin(), resultBuffer.end());
}


HANDLE IFile::openIFile(std::wstring filename){
	HANDLE result = CreateFileW(filename.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (result == INVALID_HANDLE_VALUE) throw std::system_error(system_error_code(GetLastError()));
	return result;
}

IFile::IFile()
	:fhandle(INVALID_HANDLE_VALUE)
{}

IFile::IFile(std::string filename)
	:IFile(convertName(std::move(filename)))
{}

IFile::IFile(std::wstring filename)
	:IFile(openFile(filename), filename)
{}

IFile::IFile(HANDLE handle, std::string filename) noexcept
	:IFile(handle, convertName(filename))
{}

IFile::IFile(HANDLE handle, std::wstring filename) noexcept
	:ffilename(filename),
	  fdescriptor(handle)
{}

IFile::IFile(IFile&& file) noexcept
	:ffilename(std::move(file.ffilename)),
	  fdescriptor(file.fdescriptor),
	  fsize(file.fsize)
{
	file.fdescriptor = INVALID_HANDLE_VALUE;
}

IFile& IFile::operator=(IFile file) noexcept{
	swap(*this, file);
	return *this;
}

IFile::~IFile() noexcept{
	if (fdescriptor != INVALID_HANDLE_VALUE)
		CloseHandle(fdescriptor);
}

//void swap(IFile& f1, IFile&f2) noexcept{
//	using std::swap;
//	swap(f1.ffilename, f2.ffilename);
//	swap(f1.fdescriptor, f2.fdescriptor);
//	swap(f1.fsize, f2.fsize);
//}

//------------------------------------------------------------------------------






