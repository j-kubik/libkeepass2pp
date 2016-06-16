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
#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include <system_error>
#include <iterator>
#include <cassert>
#include <algorithm>
#include <bitset>
#include <cstring>
#include <limits>

#include "platform.h"

template <typename T, typename A= std::allocator<T>>
class noInitAllocator: public A{
    typedef std::allocator_traits<A> a_t;
  public:
    template <typename U> struct rebind {
      using other =
        noInitAllocator<
          U, typename a_t::template rebind_alloc<U>
        >;
    };

    using A::A;

    template <typename U>
    void construct(U* ptr)
      noexcept(std::is_nothrow_default_constructible<U>::value) {
      ::new(static_cast<void*>(ptr)) U;
    }
    template <typename U, typename...Args>
    void construct(U* ptr, Args&&... args) {
      a_t::construct(static_cast<A&>(*this),
                     ptr, std::forward<Args>(args)...);
    }
};

template <typename T, typename A=std::allocator<T>>
using SimpleVector = std::vector<T, noInitAllocator<T,A>>;

//-----------------------------------------------------------------------------

// Just to denote unused variables and keep compiler from complainig.
// If you compiler cannot elide such call, just get a better one ;)
template <typename... Args>
inline void unused(const Args&...) noexcept{}

//-----------------------------------------------------------------------------

inline std::error_code system_error_code(int code) noexcept{
	return std::error_code(code, std::system_category());
}

//-----------------------------------------------------------------------------

std::vector<std::string> explode(const std::string& s, const char* separators);
std::string implode(const std::vector<std::string>& s, char separator);

inline void trim(std::string &s) {
	 s.erase(s.begin(), std::find_if_not(s.begin(), s.end(), [](char c){ return std::isspace(c); }));
	 s.erase(std::find_if_not(s.rbegin(), s.rend(), [](char c){ return std::isspace(c); }).base(), s.end());
}

//------------------------------------------------------------------------------

void outHex(std::ostream& o, uint8_t c);
void outHex(std::ostream& o, const uint8_t* begin, const uint8_t* end);

inline void outHex(std::ostream& o, const std::vector<uint8_t>& cs){
    outHex(o, cs.data(), cs.data() + cs.size());
}

template <std::size_t size>
inline void outHex(std::ostream& o, const std::array<uint8_t, size>& cs, std::size_t s = size){
    outHex(o, cs.data(), cs.data()+s);
}


std::vector<uint8_t> decodeBase64(std::string data);
SafeVector<uint8_t> safeDecodeBase64(std::string data);

std::string encodeBase64(const uint8_t* data, std::size_t size);
inline std::string encodeBase64(const std::vector<uint8_t>& data){
    return encodeBase64(data.data(), data.size());
}

inline std::string safeEncodeBase64(const SafeVector<uint8_t>& data){
    return encodeBase64(data.data(), data.size());
}


// This is correct independednt of machine endian, but might be inefficient
// if compiler doesn't optimize well.
template <typename T>
inline T fromLittleEndian(const uint8_t* data) noexcept{

	T result = 0;

        for (int i=sizeof(T)-1; i>=0; --i){
                result = (result << std::numeric_limits<uint8_t>::digits) | data[i];
	}
	return result;
}

template <typename T>
inline void toLittleEndian(T data, uint8_t* result) noexcept{

        for (unsigned int i=0; i<sizeof(T); ++i){
		result[i] = uint8_t(data);
                data >>= std::numeric_limits<uint8_t>::digits;
	}
}

template <typename T>
inline T fromBigEndian(const uint8_t* data) noexcept{

        T result = 0;

        for (unsigned int i=0; i<sizeof(T); ++i){
                result = (result << std::numeric_limits<uint8_t>::digits) | data[i];
        }
        return result;
}

template <typename T>
inline void toBigEndian(T data, uint8_t* result) noexcept{
        for (int i=sizeof(T)-1; i>=0; --i){
                result[i] = uint8_t(data);
                data >>= std::numeric_limits<uint8_t>::digits;
        }
}

//-----------------------------------------------------------------------------

template <typename T, unsigned int n, bool wrap = n>=(sizeof(T)*8)>
class BitRotator;

template <typename T>
class BitRotator<T, 0, false>{
public:
	static inline T left(T t) noexcept{
		return t;
	}

	static inline T right(T t) noexcept{
		return t;
	}
};

template <typename T, unsigned int n>
class BitRotator<T, n, true>: public BitRotator<T, n%(sizeof(T)*8)>{};

template <typename T, unsigned int n>
class BitRotator<T, n, false>{
public:
	static inline T left(T t) noexcept{
		return (t<<n) | (t >> (sizeof(T)*8-n));
	}

	static inline T right(T t) noexcept{
		return (t>>n) | (t << (sizeof(T)*8-n));
	}

};

template <unsigned int n, typename T>
inline T rotateLeft(T t) noexcept{
	return BitRotator<T,n>::left(t);
}

template <unsigned int n, typename T>
inline T rotateRight(T t) noexcept{
	return BitRotator<T,n>::right(t);
}

//-----------------------------------------------------------------------------

template <typename T, T tmaxValue>
class EnumFlags{
public:
	static constexpr std::size_t maxValue = std::size_t(tmaxValue);

	inline EnumFlags() noexcept{}

	inline EnumFlags(unsigned long value) noexcept
		:data(value)
	{}

	inline explicit EnumFlags(std::bitset<maxValue> value) noexcept
		:data(std::move(value))
	{}

	EnumFlags& operator&= (const EnumFlags& rhs) noexcept{ data &= rhs.data; return *this; }
	EnumFlags& operator|= (const EnumFlags& rhs) noexcept{ data |= rhs.data; return *this; }
	EnumFlags& operator^= (const EnumFlags& rhs) noexcept{ data ^= rhs.data; return *this; }
	EnumFlags operator~() const noexcept{ return EnumFlags(~data); }
	bool operator== (const EnumFlags& rhs) const noexcept{ return data == rhs.data; }
	bool operator!= (const EnumFlags& rhs) const noexcept{ return data != rhs.data; }
	bool operator[] (T pos) const{ return data[std::size_t(pos)]; }
	typename std::bitset<maxValue>::reference operator[] (T pos){ return data[std::size_t(pos)]; }

	std::size_t count() const noexcept { return data.count(); }
	constexpr std::size_t size() noexcept{ return data.size(); }
	bool test (T pos) const{ return data.test(std::size_t(pos)); }
	bool any() const noexcept { return data.any(); }
	bool all() const noexcept { return data.all(); }
	bool none() const noexcept { return data.none(); }

	EnumFlags& set() noexcept{ data.set(); return *this; }
	EnumFlags& set(T pos, bool val = true){ data.set(std::size_t(pos), val); return *this; }
	EnumFlags& reset() noexcept{ data.reset(); return *this; }
	EnumFlags& reset(T pos) noexcept{ data.reset(std::size_t(pos)); return *this; }
	EnumFlags& flip() noexcept{ data.flip(); return *this; }
	EnumFlags& flip (T pos){ data.flip(std::size_t(pos)); return *this; }

	unsigned long to_ulong() const{ return data.to_ulong(); }
	unsigned long long to_ullong() const{ return data.to_ullong(); }

	friend EnumFlags operator& (const EnumFlags& lhs, const EnumFlags& rhs) noexcept{
		return EnumFlags(lhs.data & rhs.data);
	}
	friend EnumFlags operator| (const EnumFlags& lhs, const EnumFlags& rhs) noexcept{
		return EnumFlags(lhs.data | rhs.data);
	}
	friend EnumFlags operator^ (const EnumFlags& lhs, const EnumFlags& rhs) noexcept{
		return EnumFlags(lhs.data ^ rhs.data);
	}

private:
	std::bitset<maxValue> data;
};

// ToDo: make distinction between buffer and string into C++.
//       maybe XorredString class?
class XorredBuffer{
private:
	std::vector<uint8_t> fmask;
	SafeVector<uint8_t> fbuffer;

public:

	inline XorredBuffer() noexcept
	{}

	template <typename It>
	inline XorredBuffer(It plaintextBeg, It plaintextEnd)
		:fbuffer(plaintextBeg, plaintextEnd)
	{}

	template <typename It1, typename It2>
	inline XorredBuffer(It1 xoredBeg, It1 xoredEnd, It2 maskBeg, It2 maskEnd)
		:fmask(maskBeg, maskEnd),
		  fbuffer(xoredBeg, xoredEnd)
    {
#ifndef KEEPASS2PP_NDEBUG
            assert(fmask.size() >= fbuffer.size());
 #endif
    }

	inline XorredBuffer(SafeVector<uint8_t> plaintextBuffer) noexcept
		:fbuffer(std::move(plaintextBuffer))
	{}

	inline XorredBuffer(SafeVector<uint8_t> xoredBuffer, std::vector<uint8_t> xorMask) noexcept
		:fmask(std::move(xorMask)),
		  fbuffer(std::move(xoredBuffer))
    {
#ifndef KEEPASS2PP_NDEBUG
            assert(fmask.size() >= fbuffer.size());
 #endif
    }

	inline void reXor(std::vector<uint8_t> xorMask) noexcept{
        if (xorMask.size()){
#ifndef KEEPASS2PP_NDEBUG
            assert(xorMask.size() >= fbuffer.size());
 #endif
			std::transform(fbuffer.begin(), fbuffer.end(), xorMask.begin(), fbuffer.begin(), std::bit_xor<uint8_t>());
        }
        if (fmask.size()){
			std::transform(fbuffer.begin(), fbuffer.end(), fmask.begin(), fbuffer.begin(), std::bit_xor<uint8_t>());
        }

		using std::swap;
		swap(fmask, xorMask);
	}

	inline bool hasMask() const noexcept{
		return fmask.size();
	}

	inline std::size_t size() const noexcept{
		return fbuffer.size();
	}

	inline const std::vector<uint8_t>& mask() const noexcept{
		return fmask;
	}

	inline  const SafeVector<uint8_t>& buffer() const noexcept{
		return fbuffer;
	}

	SafeVector<uint8_t> plainBuffer() const{
		if (fmask.size()){
			SafeVector<uint8_t> result;
			result.reserve(fbuffer.size());
			std::transform(fbuffer.begin(), fbuffer.end(), fmask.begin(), back_inserter(result), std::bit_xor<uint8_t>());
			return result;
		}
		return SafeVector<uint8_t>(fbuffer);
	}

	SafeString<char> plainString() const{
		if (fmask.size()){
			SafeString<char> result;
			result.reserve(fbuffer.size());
			std::transform(fbuffer.begin(), fbuffer.end(), fmask.begin(), back_inserter(result), std::bit_xor<uint8_t>());
			return result;
		}
		return SafeString<char>(fbuffer.begin(), fbuffer.end());
	}

    inline static XorredBuffer fromRaw(SafeVector<uint8_t> rawBuffer, std::vector<uint8_t> xorMask){
        std::transform(rawBuffer.begin(), rawBuffer.end(), xorMask.begin(), rawBuffer.begin(), std::bit_xor<uint8_t>());
        return XorredBuffer(std::move(rawBuffer), std::move(xorMask));
    }

    template <typename It1, typename It2>
    inline static XorredBuffer fromRaw(It1 rawBegin, It1 rawEnd, It2 maskBegin){
        SafeVector<uint8_t> rawBuffer;
        using std::distance;
        int size = distance(rawBegin, rawEnd);
        rawBuffer.reserve(size);
        std::transform(rawBegin, rawEnd, maskBegin, std::back_inserter(rawBuffer), std::bit_xor<uint8_t>());
        return XorredBuffer(std::move(rawBuffer), std::vector<uint8_t>(maskBegin, maskBegin+size));
    }

};


#endif // UTIL_H
