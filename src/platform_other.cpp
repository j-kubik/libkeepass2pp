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
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 1
#endif


#include <limits>
#include <stdexcept>
#include <cassert>
#include <memory>
#include <ctime>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../include/libkeepass2pp/platform.h"
#include "../include/libkeepass2pp/util.h"

namespace Kdbx{

//static const uint64_t t1970 = 0x19db1ded53e8000;

template <unsigned int size>
static unsigned int toUIntDate(const uint8_t (&str)[size]){
	unsigned int result = 0;
	for (unsigned int i=0; i < size; i++){
		uint8_t val = str[i];
		if (val < '0' || val > '9')
			throw std::runtime_error("Bad date format.");
		result = result*10 + (val - '0');
	}
	return result;
}

std::time_t formatTime( const char* description){

  tm timeval; 
#ifdef KEEPASS2PP_HAVE_STRPTIME
  const char* timeEnd = strptime(description, "%Y-%m-%dT%TZ", &timeval);
  if (!timeEnd || *timeEnd != 0) throw std::runtime_error("Bad date format.");
  
#else
  
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

	timeval.tm_year = toUIntDate(timeStruct->year);
	if (timeStruct->separator1 != '-') throw std::runtime_error("Bad date format.");
	timeval.tm_mon = toUIntDate(timeStruct->month);
	if (timeStruct->separator2 != '-') throw std::runtime_error("Bad date format.");
	timeval.tm_mday = toUIntDate(timeStruct->day);
	if (timeStruct->T != 'T') throw std::runtime_error("Bad date format.");
	timeval.tm_hour = toUIntDate(timeStruct->hour);
	if (timeStruct->separator3 != ':') throw std::runtime_error("Bad date format.");
	timeval.tm_min = toUIntDate(timeStruct->minute);
	if (timeStruct->separator4 != ':') throw std::runtime_error("Bad date format.");
	timeval.tm_sec = toUIntDate(timeStruct->second);
	if (timeStruct->Z != 'Z') throw std::runtime_error("Bad date format.");
	if (timeStruct->end != 0) throw std::runtime_error("Bad date format.");
	timeval.tm_wday = 0;
	timeval.tm_yday = 0;
	timeval.tm_isdst = 0;
#endif

return timegm(&timeval);
	
}

//ToDo: think of some better names here...
std::string unformatTime(std::time_t time) noexcept{
#ifdef KEEPASS2PP_HAVE_GMTIME_R
    std::tm timeval;
    gmtime_r(&time, &timeval);
#else
    std::tm& timeval = *gmtime(&time);
#endif

    char buffer[30];
    std::size_t size = strftime(buffer, 30 ,"%Y-%m-%dT%TZ", &timeval);
    return std::string(buffer, size);
}

//------------------------------------------------------------------------------

void SafeMemoryManager::zero(void* ptr, std::size_t size) noexcept{
    memset(ptr, 0, size);
//	volatile char* cptr = reinterpret_cast<volatile char*>(ptr);
//	for (std::size_t i=0; i<size; i++){
//	  cptr[i] = 0;
//	}
}

//-----------------------------------------------------------------------------------------------------

signed int Uuid::compare(const Uuid& uuid) const noexcept{
	return uuid_compare(fuid, uuid.fuid);
}

Uuid::Uuid() noexcept{
    uuid_clear(fuid);
}

Uuid::Uuid(const std::array<uint8_t, 16>& data){
	std::copy(data.begin() , data.end(), &fuid[0]);
}

Uuid::Uuid(const std::vector<uint8_t>& data){
	if (data.size() != 16)
		throw std::range_error("UUID of wrong size.");

	std::copy(data.begin() , data.end(), &fuid[0]);
}

Uuid::Uuid(const std::string& data){
	if (uuid_parse(data.c_str(), fuid) != 0)
		throw std::runtime_error("Invalid UUID.");
}

Uuid::operator std::string() const{
	char buf[37];
	uuid_unparse(fuid, &buf[0]);
	return &buf[0];
}

std::array<uint8_t, 16> Uuid::raw() const noexcept{
    std::array<uint8_t, 16> result;
    std::copy_n(&fuid[0], 16, result.begin());
    return result;
}

Uuid Uuid::nil() noexcept{
	Uuid result;
	uuid_clear(result.fuid);
	return result;
}

Uuid Uuid::generate() noexcept{
	Uuid result;
	uuid_generate(result.fuid);
	return result;
}

//-------------------------------------------------------------------------------------------------------

// Remember to also use those if implemented!!!
void ProtectedBuffer::encrypt(uint8_t* data, std::size_t size){
#warning Currently unimplemented!!!
}

void ProtectedBuffer::decrypt(uint8_t* data, std::size_t size){
#warning Currently unimplemented!!!
}


ProtectedBuffer::ProtectedBuffer(SafeString<char> plaintext){
        encrypt(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(plaintext.data())), plaintext.size());
	std::copy(plaintext.begin(), plaintext.end(), back_inserter(data));
}


ProtectedBuffer::ProtectedBuffer(SafeVector<uint8_t> plaintext){
        encrypt(plaintext.data(), plaintext.size());
	std::copy(plaintext.begin(), plaintext.end(), back_inserter(data));
}

SafeString<char> ProtectedBuffer::toString(){
	SafeString<char> result(data.begin(), data.end());
	decrypt(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(result.data())), result.size());
	return result;
}

SafeVector<uint8_t> ProtectedBuffer::toBuffer(){
	SafeVector<uint8_t> result(data.begin(), data.end());
	decrypt(result.data(), result.size());
	return result;
}

//------------------------------------------------------------------------------------------------------------

}







