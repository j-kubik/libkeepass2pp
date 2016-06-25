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
#ifndef KDBXCRYPTORANDOM_H
#define KDBXCRYPTORANDOM_H

#include <vector>
#include <array>
#include <cstdint>
#include <memory>

#include "util.h"

namespace Kdbx{

class RandomStream{
public:
	enum class Algorithm: uint32_t{
		Null = 0,

		/// A variant of the ARCFour algorithm (RC4 incompatible).
		ArcFourVariant = 1,

		/// Salsa20 stream cipher algorithm.
		Salsa20 = 2,

		Count = 3
	};

    typedef std::unique_ptr<RandomStream> Ptr;

    RandomStream(const RandomStream&) = delete;
    RandomStream(RandomStream&&) = delete;
    RandomStream& operator=(const RandomStream&) = delete;
    RandomStream& operator=(RandomStream&&) = delete;

    inline RandomStream() noexcept{}
    virtual ~RandomStream(){}

	virtual void readRaw(uint8_t* begin, uint8_t* end) noexcept =0;
    virtual SafeVector<uint8_t> read(std::size_t size) =0;

    static Ptr randomStream(Algorithm algorithm, const SafeVector<uint8_t>& key);
};

class Null: public RandomStream{
public:

    inline Null(const SafeVector<uint8_t>&) noexcept
    {}

    inline void readRaw(uint8_t* dataBegin, uint8_t* dataEnd) noexcept override{
        memset(dataBegin, 0, dataEnd - dataBegin);
    }

    inline SafeVector<uint8_t> read(std::size_t size) override{
        return SafeVector<uint8_t>(size);
    }

    template <std::size_t size>
    std::array<uint8_t, size> readFixed() noexcept{
        return std::array<uint8_t, size>();
    }

};

class Salsa20: public RandomStream{
private:
	void reload() noexcept;

	std::array<uint32_t, 16> state;
	std::array<uint8_t, 64> buffer;
	std::array<uint8_t, 64>::iterator bufferPos;

public:

    Salsa20(const SafeVector<uint8_t>& key) noexcept;

	void readRaw(uint8_t* dataBegin, uint8_t* dataEnd) noexcept override;
    SafeVector<uint8_t> read(std::size_t size) override;

};

//ArcFourVariant;

class ArcFourVariant: public RandomStream{
private:
	std::array<uint8_t, 256> state;
	uint8_t m_i;
	uint8_t m_j;

public:
    ArcFourVariant(const SafeVector<uint8_t>& key);

    ~ArcFourVariant();

	void readRaw(uint8_t* begin, uint8_t* end) noexcept override;
    SafeVector<uint8_t> read(std::size_t size) override;

};

}

#endif // KDBXCRYPTORANDOM_H
