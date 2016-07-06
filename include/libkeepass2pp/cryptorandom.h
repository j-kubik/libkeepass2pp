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

/** @brief An interface that encapsulates a concept of pseudo-random stream.
 *
 * Pseudo random stream is a stream of bytes that is derived form a relatively
 * short key, and is always the same for a given key.*/
class RandomStream{
public:

    /** @brief Currently supported algorithms. */
	enum class Algorithm: uint32_t{
		Null = 0,

        //! A variant of the ARCFour algorithm (RC4 incompatible).
		ArcFourVariant = 1,

        //! Salsa20 stream cipher algorithm.
		Salsa20 = 2,

		Count = 3
	};

    /** @brief Uniqiue owning pointer to a RandomStream object. */
    typedef std::unique_ptr<RandomStream> Ptr;

    RandomStream() = default;
    RandomStream(const RandomStream&) = delete;
    RandomStream(RandomStream&&) = delete;
    RandomStream& operator=(const RandomStream&) = delete;
    RandomStream& operator=(RandomStream&&) = delete;

    /** Destroys a RandomStream. */
    virtual ~RandomStream(){}

    /** @brief Reads bytes into a buffer.
     * @param begin Pointer to the begining of the buffer;
     * @param end Pointer to a first byte after the end of the buffer;
     *
     * It advances internal stream positon by amount of bytes read.
     */
	virtual void readRaw(uint8_t* begin, uint8_t* end) noexcept =0;

    /** @brief Reads bytes specified number bytes from pseudo-random stream.
     * @param size Number of bytes to read and return;
     * @return Buffer containing pseudo-random bytes.
     *
     * It advances internal stream positon by amount of bytes read.
     */
    virtual SafeVector<uint8_t> read(std::size_t size) =0;

    /** @brief Constructs new RandomStream and returns an owning pointer to it.
     * @param algorithm Algorithm used to generate pseudo-random stream;
     * @param key Buffer used as key to initialize pseudo-random stream;
     */
    static Ptr randomStream(Algorithm algorithm, const SafeVector<uint8_t>& key);
};

/** @brief Null random stream.
 *
 * Ignores initialization key, and returns only zeros.
 */
class Null: public RandomStream{
public:

    inline Null() noexcept
    {}

    inline Null(const SafeVector<uint8_t>&) noexcept
    {}

    /** @brief Implemetation of RandomStream::readRaw. */
    inline void readRaw(uint8_t* dataBegin, uint8_t* dataEnd) noexcept override{
        memset(dataBegin, 0, dataEnd - dataBegin);
    }

    /** @brief Implemetation of RandomStream::read. */
    inline SafeVector<uint8_t> read(std::size_t size) override{
        return SafeVector<uint8_t>(size);
    }

    /** @brief Returns a fixed-size array of pseudo-random bytes. */
    template <std::size_t size>
    std::array<uint8_t, size> readFixed() noexcept{
        return std::array<uint8_t, size>();
    }

};

/** @brief Implementation of a Sals20 algorithm. */
class Salsa20: public RandomStream{
private:
	void reload() noexcept;

	std::array<uint32_t, 16> state;
	std::array<uint8_t, 64> buffer;
	std::array<uint8_t, 64>::iterator bufferPos;

public:

    /** @brief Initializes Sals20 with provided key. */
    Salsa20(const SafeVector<uint8_t>& key) noexcept;

    /** Destroys an Sals20 object. */
    ~Salsa20() noexcept;

    /** @brief Implemetation of RandomStream::readRaw. */
    void readRaw(uint8_t* dataBegin, uint8_t* dataEnd) noexcept override;

    /** @brief Implemetation of RandomStream::read. */
    SafeVector<uint8_t> read(std::size_t size) override;

};

/** @brief A modified version of RC4 algorythm.
 *
 * This not exact implementation of RC4 algorythm, but a slight modification
 * written to match original KeePass 2 sources.
 *
 * I am not sure why actual RC4 was not implemented by KeePass 2 authors.
 */
class ArcFourVariant: public RandomStream{
private:
	std::array<uint8_t, 256> state;
	uint8_t m_i;
	uint8_t m_j;

public:
    /** @brief Initializes ArcFourVariant with provided key. */
    ArcFourVariant(const SafeVector<uint8_t>& key);

    /** Destroys a ArcFourVariant object. */
    ~ArcFourVariant();

    /** @brief Implemetation of RandomStream::readRaw. */
    void readRaw(uint8_t* begin, uint8_t* end) noexcept override;

    /** @brief Implemetation of RandomStream::read. */
    SafeVector<uint8_t> read(std::size_t size) override;

};

}

#endif // KDBXCRYPTORANDOM_H
