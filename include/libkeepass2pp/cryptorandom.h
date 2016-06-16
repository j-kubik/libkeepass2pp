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


class KdbxRandomStream{
public:
	enum class Algorithm: uint32_t{
		Null = 0,

		/// A variant of the ARCFour algorithm (RC4 incompatible).
		ArcFourVariant = 1,

		/// Salsa20 stream cipher algorithm.
		Salsa20 = 2,

		Count = 3
	};

	typedef std::unique_ptr<KdbxRandomStream> Ptr;

	KdbxRandomStream(const KdbxRandomStream&) = delete;
	KdbxRandomStream(KdbxRandomStream&&) = delete;
	KdbxRandomStream& operator=(const KdbxRandomStream&) = delete;
	KdbxRandomStream& operator=(KdbxRandomStream&&) = delete;

	inline KdbxRandomStream() noexcept{}
	virtual ~KdbxRandomStream(){}

	virtual void readRaw(uint8_t* begin, uint8_t* end) noexcept =0;
	virtual std::vector<uint8_t> read(std::size_t size) =0;

	static Ptr randomStream(Algorithm algorithm, const std::vector<uint8_t>& key);
};

class KdbxNull: public KdbxRandomStream{
public:

    inline KdbxNull(const std::vector<uint8_t>&) noexcept
    {}

    inline void readRaw(uint8_t* dataBegin, uint8_t* dataEnd) noexcept override{
        memset(dataBegin, 0, dataEnd - dataBegin);
    }

    inline std::vector<uint8_t> read(std::size_t size) override{
        return std::vector<uint8_t>(size);
    }

    template <std::size_t size>
    std::array<uint8_t, size> readFixed() noexcept{
        return std::array<uint8_t, size>();
    }

};

class KdbxSalsa20: public KdbxRandomStream{
private:
	void reload() noexcept;

	std::array<uint32_t, 16> state;
	std::array<uint8_t, 64> buffer;
	std::array<uint8_t, 64>::iterator bufferPos;

public:

	KdbxSalsa20(const std::vector<uint8_t>& key) noexcept;

	void readRaw(uint8_t* dataBegin, uint8_t* dataEnd) noexcept override;
	std::vector<uint8_t> read(std::size_t size) override;

	template <std::size_t size>
	std::array<uint8_t, size> readFixed() noexcept{
		std::array<uint8_t, size> result;
		readRaw(result.data(), result.data() + size);
		return result;
	}

};

//ArcFourVariant;

class KdbxArcFourVariant: public KdbxRandomStream{
private:
	std::array<uint8_t, 256> state;
	uint8_t m_i;
	uint8_t m_j;

public:
	KdbxArcFourVariant(const std::vector<uint8_t>& key);

	void readRaw(uint8_t* begin, uint8_t* end) noexcept override;
	std::vector<uint8_t> read(std::size_t size) override;

	template <std::size_t size>
	std::array<uint8_t, size> readFixed(){
		std::array<uint8_t, size> result;
		readRaw(result.data(), result.data() + size);
		return result;
	}

};



#endif // KDBXCRYPTORANDOM_H
