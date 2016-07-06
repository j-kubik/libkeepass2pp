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
#include <openssl/sha.h>

#include "../include/libkeepass2pp/cryptorandom.h"
#include "../include/libkeepass2pp/wrappers.h"

namespace Kdbx{

RandomStream::Ptr RandomStream::randomStream(Algorithm algorithm, const SafeVector<uint8_t>& key){
	switch (algorithm){
    case Algorithm::Null:
        return RandomStream::Ptr(new Null(key));
	case Algorithm::ArcFourVariant:
        return RandomStream::Ptr(new ArcFourVariant(key));
	case Algorithm::Salsa20:
        return RandomStream::Ptr(new Salsa20(key));
	default:
		throw std::runtime_error("Unknown crypto-random stream type.");
	}
}


//-------------------------------------------------------------------------------------------

static constexpr uint32_t sigma[] = {
	0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
};

void Salsa20::reload() noexcept{
	std::array<uint32_t, 16> current = state;

	for (unsigned int i=0; i<10; i++){
		current[ 4] ^= rotateLeft< 7>(current[ 0] + current[12]);
		current[ 8] ^= rotateLeft< 9, uint32_t>(current[ 4] + current[ 0]);
		current[12] ^= rotateLeft<13, uint32_t>(current[ 8] + current[ 4]);
		current[ 0] ^= rotateLeft<18, uint32_t>(current[12] + current[ 8]);
		current[ 9] ^= rotateLeft< 7, uint32_t>(current[ 5] + current[ 1]);
		current[13] ^= rotateLeft< 9, uint32_t>(current[ 9] + current[ 5]);
		current[ 1] ^= rotateLeft<13, uint32_t>(current[13] + current[ 9]);
		current[ 5] ^= rotateLeft<18, uint32_t>(current[ 1] + current[13]);
		current[14] ^= rotateLeft< 7, uint32_t>(current[10] + current[ 6]);
		current[ 2] ^= rotateLeft< 9, uint32_t>(current[14] + current[10]);
		current[ 6] ^= rotateLeft<13, uint32_t>(current[ 2] + current[14]);
		current[10] ^= rotateLeft<18, uint32_t>(current[ 6] + current[ 2]);
		current[ 3] ^= rotateLeft< 7, uint32_t>(current[15] + current[11]);
		current[ 7] ^= rotateLeft< 9, uint32_t>(current[ 3] + current[15]);
		current[11] ^= rotateLeft<13, uint32_t>(current[ 7] + current[ 3]);
		current[15] ^= rotateLeft<18, uint32_t>(current[11] + current[ 7]);
		current[ 1] ^= rotateLeft< 7, uint32_t>(current[ 0] + current[ 3]);
		current[ 2] ^= rotateLeft< 9, uint32_t>(current[ 1] + current[ 0]);
		current[ 3] ^= rotateLeft<13, uint32_t>(current[ 2] + current[ 1]);
		current[ 0] ^= rotateLeft<18, uint32_t>(current[ 3] + current[ 2]);
		current[ 6] ^= rotateLeft< 7, uint32_t>(current[ 5] + current[ 4]);
		current[ 7] ^= rotateLeft< 9, uint32_t>(current[ 6] + current[ 5]);
		current[ 4] ^= rotateLeft<13, uint32_t>(current[ 7] + current[ 6]);
		current[ 5] ^= rotateLeft<18, uint32_t>(current[ 4] + current[ 7]);
		current[11] ^= rotateLeft< 7, uint32_t>(current[10] + current[ 9]);
		current[ 8] ^= rotateLeft< 9, uint32_t>(current[11] + current[10]);
		current[ 9] ^= rotateLeft<13, uint32_t>(current[ 8] + current[11]);
		current[10] ^= rotateLeft<18, uint32_t>(current[ 9] + current[ 8]);
		current[12] ^= rotateLeft< 7, uint32_t>(current[15] + current[14]);
		current[13] ^= rotateLeft< 9, uint32_t>(current[12] + current[15]);
		current[14] ^= rotateLeft<13, uint32_t>(current[13] + current[12]);
		current[15] ^= rotateLeft<18, uint32_t>(current[14] + current[13]);
	}

	for (unsigned int i=0; i<16; i++){
		current[i] += state[i];
	}

	for (unsigned int i=0; i<16; i++){
		toLittleEndian(current[i], &buffer[i*4]);
	}

	if (++state[8] == 0) state[9]++;
}

Salsa20::Salsa20(const SafeVector<uint8_t>& key) noexcept
	:bufferPos(buffer.end()){

    OSSL::Digest d(EVP_sha256());
    d.update(key.data(), key.size());
	std::array<uint8_t, 32> keySha256;
    d.final(keySha256);

	uint8_t iv[8]={ 0xE8, 0x30, 0x09, 0x4B,
		0x97, 0x20, 0x5D, 0x2A };

	state[1] = fromLittleEndian<uint32_t>(&keySha256[0]);
	state[2] = fromLittleEndian<uint32_t>(&keySha256[4]);
	state[3] = fromLittleEndian<uint32_t>(&keySha256[8]);
	state[4] = fromLittleEndian<uint32_t>(&keySha256[12]);
	state[11] = fromLittleEndian<uint32_t>(&keySha256[16]);
	state[12] = fromLittleEndian<uint32_t>(&keySha256[20]);
	state[13] = fromLittleEndian<uint32_t>(&keySha256[24]);
	state[14] = fromLittleEndian<uint32_t>(&keySha256[28]);
	state[0] = sigma[0];
	state[5] = sigma[1];
	state[10] = sigma[2];
	state[15] = sigma[3];
	state[6] = fromLittleEndian<uint32_t>(&iv[0]);
	state[7] = fromLittleEndian<uint32_t>(&iv[4]);
	state[8] = 0;
	state[9] = 0;

    for (unsigned int i=0; i<32; i++){
        keySha256[i] = 0;
    }
}

Salsa20::~Salsa20(){
    for (uint32_t& i: state)
        i = 0;

    for (uint8_t& i: buffer)
        i = 0;
}

void Salsa20::readRaw(uint8_t* dataBegin, uint8_t* dataEnd) noexcept{

   auto copyEnd = bufferPos + std::min<std::ptrdiff_t>(buffer.end() - bufferPos, dataEnd - dataBegin);
   dataBegin = std::copy(bufferPos, copyEnd, dataBegin);

   while (dataBegin < dataEnd){
	   reload();
	   copyEnd = buffer.begin() + std::min<std::ptrdiff_t>(buffer.size(), dataEnd - dataBegin);
	   dataBegin = std::copy(buffer.begin(), copyEnd, dataBegin);
   }

   bufferPos = copyEnd;
}

SafeVector<uint8_t> Salsa20::read(std::size_t size){
    SafeVector<uint8_t> result;
	result.reserve(size);

	auto copyEnd = bufferPos + std::min<std::ptrdiff_t>(buffer.end() - bufferPos, size);
	result.insert(result.end(), bufferPos, copyEnd);

	while (size - result.size() > 0){
		reload();
		copyEnd = buffer.begin() + std::min<std::ptrdiff_t>(buffer.size(), size - result.size());
		result.insert(result.end(), buffer.begin(), copyEnd);
	}

	bufferPos = copyEnd;
	return result;
}

//--------------------------------------------------------------------------------------------

ArcFourVariant::ArcFourVariant(const SafeVector<uint8_t>& key)
	:m_i(0),
	   m_j(0)
{
	for (unsigned int i=0; i<256; i++) state[i] = i;

	uint8_t j =0;
	std::size_t keyPos = 0;

	using std::swap;
	for (unsigned int i=0; i<256; i++){
		j += state[i] + key[keyPos++];
        swap(state[0], state[j]);
		if (keyPos >= key.size())
			keyPos = 0;
	}

    read(512);
}

ArcFourVariant::~ArcFourVariant(){
    for (unsigned int i=0; i<256; i++)
        state[i] = 0;
}

void ArcFourVariant::readRaw(uint8_t* begin, uint8_t* end) noexcept{
	using std::swap;

	for (; begin<end; ++begin){
		m_j += state[++m_i];
		swap(state[m_i], state[m_j]);
		*begin = state[uint8_t(state[m_i] + state[m_j])];
	}
}

SafeVector<uint8_t> ArcFourVariant::read(std::size_t size){
    SafeVector<uint8_t> result;
	result.reserve(size);
	using std::swap;

	while (size-- > 0){
		m_j += state[++m_i];
		swap(state[m_i], state[m_j]);
		result.push_back(state[uint8_t(state[m_i] + state[m_j])]);
	}
	return result;
}

}
