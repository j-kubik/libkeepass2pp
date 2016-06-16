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
#ifndef PLATFORM_H
#define PLATFORM_H

#include <string>
#include <vector>
#include <array>
#include <stdexcept>
#include <ctime>

#ifdef _WIN32
    #include <windows.h>
    #include <guiddef.h>
#else
    #include <uuid/uuid.h>
#endif

#include "libkeepass2pp/keepass2pp_config.h"

#ifdef _WIN32
    typedef SYSTEMTIME DateTimeStruct;
#elif KEEPASS2PP_HAVE_STRPTIME
    #include <time.h>
    typedef tm DateTimeStruct;
#else
    // This shouldbe handled by configure script, this is just last-hance check...
    #error Time formating not yet implemented for other platforms.
#endif

std::time_t formatTime(const char* description);
std::string unformatTime(std::time_t time) noexcept;

//------------------------------------------------------------------------------

enum DoNotInitEnum{
    DoNotInit
};

// For now just a malloc/free combo - someday there should be a full manager here.
class SafeMemoryManager{
public:

    static void* allocate(std::size_t size){
        void* result = malloc(size);
        if (!result)
            throw std::bad_alloc();
        return result;
    }

    static void zero(void* ptr, std::size_t size) noexcept;

    static void deallocate(void* ptr, std::size_t size) noexcept{
        zero(ptr, size);
        free(ptr);
    }

};


// ToDo: since meory locking is page-based, the entire concept here is fundamentally flawed.
//       In order to get this right writing full memory allocator might be required.

template <typename T>
class SafeAllocator;

template <typename T>
class SafeAllocator: public std::allocator<T>{
public:

    inline typename std::allocator<T>::pointer allocate( typename std::allocator<T>::size_type n, std::allocator<void>::const_pointer /*hint*/ = 0 ){
        return reinterpret_cast<T*>(SafeMemoryManager::allocate(sizeof(T)*n));
        //typename std::allocator<T>::pointer result = std::allocator<T>::allocate(n, hint);
		//SafeAllocator<void>::lock(result, sizeof(T)*n);
        //return result;
	}


	inline void deallocate( typename std::allocator<T>::pointer p, typename std::allocator<T>::size_type n ){
        SafeMemoryManager::deallocate(p, n);
        //SafeAllocator<void>::zero(p, sizeof(T)*n);
		//SafeAllocator<void>::unlock(p, sizeof(T)*n);
        //std::allocator<T>::deallocate(p, n);
	}

	template< class U > struct rebind { typedef SafeAllocator<U> other; };

};

template <typename T>
using SafeVector = std::vector<T, SafeAllocator<T>>;
template <typename T>
using SafeString = std::basic_string<T, std::char_traits<T>, SafeAllocator<T>>;



class Uuid{
private:
#ifdef _WIN32
        typedef GUID UUIDType;
#else
        typedef uuid_t UUIDType;  
#endif
	
	UUIDType fuid;
private:
	signed int compare(const Uuid& uuid) const noexcept;
public:

    inline Uuid(DoNotInitEnum) noexcept{}

    Uuid() noexcept;
	explicit Uuid(const std::array<uint8_t, 16>& data);
	explicit Uuid(const std::vector<uint8_t>& data);
	explicit Uuid(const std::string& data);
	explicit Uuid(const std::wstring& data);

	inline explicit operator bool() const noexcept{
		return nil() != *this;
	}

	inline bool operator==(const Uuid& uuid) const noexcept{
		return compare(uuid) == 0;
	}

	inline bool operator!=(const Uuid& uuid) const noexcept{
		return compare(uuid) != 0;
	}

	inline bool operator<(const Uuid& uuid) const noexcept{
		return compare(uuid) < 0;
	}

	inline bool operator>(const Uuid& uuid) const noexcept{
		return compare(uuid) > 0;
	}

	inline bool operator<=(const Uuid& uuid) const noexcept{
		return compare(uuid) <= 0;
	}

	inline bool operator>=(const Uuid& uuid) const noexcept{
		return compare(uuid) >= 0;
	}

    std::array<uint8_t, 16> raw() const noexcept;

	explicit operator std::string() const;
	explicit operator std::wstring() const;

	static Uuid nil() noexcept;
	static Uuid generate() noexcept;

};

class ProtectedBuffer{
private:
	static void encrypt(uint8_t* data, std::size_t size);
	static void decrypt(uint8_t* data, std::size_t size);
	
	std::vector<uint8_t> data;
public:

	inline ProtectedBuffer() noexcept
	{}

	ProtectedBuffer(SafeString<char> plaintext);
	ProtectedBuffer(SafeVector<uint8_t> plaintext);

	SafeString<char> toString();
	SafeVector<uint8_t> toBuffer();
};


  






#endif // PLATFORM_H
