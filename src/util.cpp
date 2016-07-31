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
#include <stdexcept>
#include <memory>

#include "../include/libkeepass2pp/util.h"

namespace Kdbx{

std::vector<std::string> explode(const std::string& s, const char* separators){

	std::vector<std::string> result;
	std::size_t bpos = 0;
	std::size_t epos;

	while ((epos = s.find_first_of(separators, bpos)) != std::string::npos){
		if (bpos != epos)
			result.emplace_back(s, bpos, epos-bpos);
		bpos = epos+1;
	}

	return result;
}

std::string implode(const std::vector<std::string>& items, char separator){
    if (items.empty())
        return std::string();

    std::stringstream s;
    std::vector<std::string>::const_iterator i = items.begin();
    s << *i;
    for (++i; i != items.end(); ++i){
        s << separator << *i;
    }
    return s.str();
}

void outHex(std::ostream& o, uint8_t c){
    static const char symbols[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	o << symbols[c >> 4] << symbols[c & 0x0f];
}

void outHex(std::ostream& o, const uint8_t* begin, const uint8_t* end){
    for (; begin!= end; ++begin){
        outHex(o, *begin);
	}
}


uint8_t inHex(char c){
    if (c >= '0' && c <='9')
        return c - '0';
    if (c >='a' && c <= 'f')
        return c - 'a' + 10;
    if (c >='A' && c <= 'F')
        return c - 'A' + 10;
    throw std::runtime_error("Bad hexadecimal number");
}

uint8_t inHex(char c1, char c2){
    return (inHex(c1) << 4) | inHex(c2);
}

std::vector<uint8_t> inHex(const char* begin, const char* end){
    assert(begin <= end);
    if ((end-begin)%2)
        throw std::runtime_error("Bad hexadecimal number");
    std::vector<uint8_t> result;
    result.reserve((end-begin)/2);
    while (begin!=end){
        result.push_back(inHex(*begin, *(begin+1)));
        begin += 2;
    }
    return result;
}

uint8_t inHex(std::istream& s){
    int c1 = s.get();
    if (c1 == std::char_traits<char>::eof())
        throw std::runtime_error("Hex buffer of wrong length.");
    int c2 = s.get();
    if (c2 == std::char_traits<char>::eof())
        throw std::runtime_error("Hex buffer of wrong length.");
    return inHex(c1, c2);
}

static uint8_t decodeBase64Char(char c){
	if (c >='A' && c <= 'Z')
		return c - 'A';
	if (c >='a' && c <= 'z')
		return c - 'a' + 26;
	if (c >='0' && c <= '9')
		return c - '0' + 52;
	if (c == '+' || c == '-')
		return 62;
	if (c == '/' || c == '_')
		return 63;
	throw std::runtime_error("Invalid base64 characters.");
}

static char encodeBase64Byte(uint8_t c) noexcept{
    assert(c < 64);
    if (c < 26)
        return c + 'A';
    if (c < 52)
        return c - 26 + 'a';
    if (c < 62)
        return c - 52 + '0';
    if (c == 62)
        return '+';
    if (c == 63)
        return '/';
    return 0; // This is just to keep compiler from complaining...
}

std::vector<uint8_t> decodeBase64(std::string data){
	std::vector<uint8_t> result;

	if (data.back() == '=') data.pop_back();
	if (data.back() == '=') data.pop_back();

	int length = (data.size()/4);

	uint8_t c1,c2,c3,c4;
	for (int i=0; i<length; i++){
		c1 = decodeBase64Char(data[i*4]);
		c2 = decodeBase64Char(data[i*4+1]);
		result.push_back((c1 << 2) | (c2 >> 4));
		c3 = decodeBase64Char(data[i*4+2]);
		result.push_back((c2 << 4) | (c3 >> 2));
		c4 = decodeBase64Char(data[i*4+3]);
		result.push_back((c3 << 6) | (c4));
	}

	switch (data.size() % 4){
	case 0: break;
    case 1: throw std::runtime_error("Invalid base64 string.");
	case 2:
		c1 = decodeBase64Char(data[length*4]);
		c2 = decodeBase64Char(data[length*4+1]);
		result.push_back((c1 << 2) | (c2 >> 4));
		break;
	case 3:
		c1 = decodeBase64Char(data[length*4]);
		c2 = decodeBase64Char(data[length*4+1]);
		result.push_back((c1 << 2) | (c2 >> 4));
		c3 = decodeBase64Char(data[length*4+2]);
		result.push_back((c2 << 4) | (c3 >> 2));
		break;
	}

	return result;
}

SafeVector<uint8_t> safeDecodeBase64(SafeString<char> data){
	SafeVector<uint8_t> result;

	if (data.back() == '=') data.pop_back();
	if (data.back() == '=') data.pop_back();

	int length = (data.size()/4);

	uint8_t c1,c2,c3,c4;
	for (int i=0; i<length; i++){
		c1 = decodeBase64Char(data[i*4]);
		c2 = decodeBase64Char(data[i*4+1]);
		result.push_back((c1 << 2) | (c2 >> 4));
		c3 = decodeBase64Char(data[i*4+2]);
		result.push_back((c2 << 4) | (c3 >> 2));
		c4 = decodeBase64Char(data[i*4+3]);
		result.push_back((c3 << 6) | (c4));
	}

	switch (data.size() % 4){
	case 0: break;
    case 1: throw std::runtime_error("Invalid base64 string.");
	case 2:
		c1 = decodeBase64Char(data[length*4]);
		c2 = decodeBase64Char(data[length*4+1]);
		result.push_back((c1 << 2) | (c2 >> 4));
		break;
	case 3:
		c1 = decodeBase64Char(data[length*4]);
		c2 = decodeBase64Char(data[length*4+1]);
		result.push_back((c1 << 2) | (c2 >> 4));
		c3 = decodeBase64Char(data[length*4+2]);
		result.push_back((c2 << 4) | (c3 >> 2));
		break;
	}

	return result;
}

std::string encodeBase64(const uint8_t* data, std::size_t size){
    int fullBlocks = size / 3;
    std::string result;
    result.reserve(((size+2)/3)*4);

    for (int i=0; i< fullBlocks; ++i){
        result.push_back(encodeBase64Byte(data[i*3] >> 2));
        result.push_back(encodeBase64Byte((data[i*3] << 4 | data[i*3+1] >> 4)& 0x3f));
        result.push_back(encodeBase64Byte((data[i*3+1] << 2 | data[i*3+2] >> 6) &0x3f));
        result.push_back(encodeBase64Byte(data[i*3+2] &0x3f));
    }
    switch (size %3){
    case 2:
        result.push_back(encodeBase64Byte(data[size - 2] >> 2));
        result.push_back(encodeBase64Byte((data[size - 2] << 4 | data[size - 1] >> 4) & 0x3f));
        result.push_back(encodeBase64Byte((data[size - 1] << 2) &0x3f));
        result.push_back('=');
        break;
    case 1:
        result.push_back(encodeBase64Byte(data[size - 1] >> 2));
        result.push_back(encodeBase64Byte((data[size - 1] << 4) & 0x3f));
        result.push_back('=');
        result.push_back('=');
        break;
    default:;
    }

    return result;
}

}




