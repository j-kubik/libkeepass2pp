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
#ifndef LINKS_H
#define LINKS_H

#include "wrappers.h"
#include "pipeline.h"
#include "platform.h"

namespace Kdbx{

//ToDo:: istream is inherently blocking. Is this a problem?
/** @brief Pipeline link that takes ownership of an istream object.
 *
 * It modifies exception flags of the istream object to std::istream::badbit.
 * It reads data from an istream until eof() returns true, or an exception is
 * thrown.
 */
class IStreamLink: public Pipeline::OutLink{
private:

        std::unique_ptr<std::istream> ffile;
        std::string filename;

        /** @brief Ovveride of Pipeline::OutLink method. */
        void runThread() override;

public:
        /** @brief Opens a file and uses it as an input stream.
         * @param filename Name of a file to open.
         *
         * File is open after the pipeline is started, in link's own thread in
         * order to avoid blocking the thread that start the pipeline.
         */
        inline IStreamLink(std::string filename) noexcept
            :filename(std::move(filename))
        {}

        /** @brief Takes an owning pointer to an input stream.
         * @param file Inupt stream to read the data from;
         * @param Optional filename that may be used in error message;
         *
         * @note Currently there is no way to use std::cin with this class.
         */
        inline IStreamLink(std::unique_ptr<std::istream> file, std::string filename= std::string()) noexcept
                :ffile(std::move(file)),
                  filename(std::move(filename))
        {}

};

/** @brief Pipeline link that takes ownership of an ostream object.
 *
 * It modifies exception flags of the ostream object to std::ostream::badbit.
 * It writes data to the ostream until pinpeline stream end, or an exception is
 * thrown.
 */
class OStreamLink: public Pipeline::InLink{
private:
        std::unique_ptr<std::ostream> ffile;
        std::string filename;
        std::promise<std::unique_ptr<std::ostream>> finished;

        /** @brief Ovveride of Pipeline::InLink method. */
        void runThread() override;
public:

        /** @brief Opens a file and uses it as an output stream.
         * @param filename Name of a file to open.
         *
         * File is open after the pipeline is started, in link's own thread in
         * order to avoid blocking the thread that start the pipeline.
         */
        inline OStreamLink(std::string filename) noexcept
            :filename(std::move(filename))
        {}

        /** @brief Takes an owning pointer to an output stream.
         * @param file Output stream to write the data to;
         * @param Optional filename that may be used in error message;
         *
         * @note Currently there is no way to use std::cout or std::cerr with
         *       this class.
         */
        inline OStreamLink(std::unique_ptr<std::ostream> file, std::string filename= std::string()) noexcept
                :ffile(std::move(file)),
                  filename(std::move(filename))
        {}

        /** @brief Returns a future object that receives an owning pointer to
         *         an output stream.
         *
         * This method can be called at most once per OStreamLink object. It can
         * be used if additional data is to be writen to the output stream after
         * pipeline data. The future gets a value as soon as the link is ready
         * to flush and release it's stream. Note that the stream is returned
         * even if the pipeline was aborted and full data was not written to the
         * stream.
         *
         * If an OStreamLink was created with existing std::ostream, pointer
         * returned by this future is guaranted to poin to the same object that
         * was passed to the constructor.
         */

        std::future<std::unique_ptr<std::ostream>> getFuture() noexcept{
            return finished.get_future();
        }

};

/** @brief Pipeline link that takes ownership of an ostream object.
 *
 * It modifies exception flags of the ostream object to std::ostream::badbit.
 * It writes data to the ostream until pinpeline stream end, or an exception is
 * thrown. It also passes it's data without modification to the next link.
 *
 * @note If writing to the output stream causes an exception, entire pipeline is
 *       aborted.
 */
class OStreamTeeLink: public Pipeline::InOutLink{
private:
        std::unique_ptr<std::ostream> ffile;
        std::string filename;

        /** @brief Ovveride of Pipeline::InOutLink method. */
        void runThread() override;

public:
        /** @brief Opens a file and uses it as an output stream.
         * @param filename Name of a file to open.
         *
         * File is open after the pipeline is started, in link's own thread in
         * order to avoid blocking the thread that start the pipeline.
         */
        inline OStreamTeeLink(std::string filename) noexcept
            :filename(std::move(filename))
        {}

        /** @brief Takes an owning pointer to an output stream.
         * @param file Output stream to write the data to;
         * @param Optional filename that may be used in error message;
         *
         * @note Currently there is no way to use std::cout or std::cerr with
         *       this class.
         */
        inline OStreamTeeLink(std::unique_ptr<std::ostream> file, std::string filename= std::string()) noexcept
                :ffile(std::move(file)),
                  filename(std::move(filename))
        {}

};

/** @brief Performs an OpenSSL cipher on pipeline data.*/
class EvpCipher: public Pipeline::InOutLink{
private:
    OSSL::EvpCipher cipher;

    /** @brief Ovveride of Pipeline::InOutLink method. */
    std::size_t requestedMaxSize() noexcept override;

    /** @brief Ovveride of Pipeline::InOutLink method. */
    void runThread() override;
public:
    /** @brief Initializes a cipher.
     * @param cipher Cipher to use on pipeline data. It must be valid and set
     * up for data processing.
     */
    inline EvpCipher(OSSL::EvpCipher cipher) noexcept
        :cipher(std::move(cipher))
    {}

    /** @brief returns OpenSSL cipher context. */
    inline const OSSL::EvpCipher& context() noexcept{
        return cipher;
    }

};


/** @brief Performs hash-stream algorith on pipeline data.
 *
 * Hash-stream is KeePass specific operation. It's algorith is as follows:
 *  - Divide input data into arbitrary-length portions;
 *  - Prepend each data portion with a 40-byte header that consist of:
 *     * 4-byte zero based portion index (little endian);
 *     * 32-byte SHA 256 digest of original data portion;
 *     * 4-byte length of original data portion (little endian);
 *  - Output stream consists of:
 *     * 32-byte header of aritrary bytes that are specified as configureation.
 *     * all prepeneded data portions in the same order as the original data
 *       portions were received.
 *     * last 40-byte header with apropriate index, and witch checksum and size
 *       set all to zeros.
 */
class HashStreamLink: public Pipeline::InOutLink{
private:
        const std::array<uint8_t, 32> initBytes;

        /** @brief Ovveride of Pipeline::InOutLink method. */
        std::size_t requestedMaxSize() noexcept override;

        /** @brief Ovveride of Pipeline::InOutLink method. */
        void runThread() override;
public:

        /** @brief Initializes hash-stream link.
         * @param initBytes 32 bytes to be used as output stream header.
         */
        inline HashStreamLink(const std::array<uint8_t,32>& initBytes) noexcept
                :initBytes(initBytes)
        {}
};

/** @brief Performs operation inverse to HashStreamLink.
 *
 * It can optionally validate the header against provided buffer. If header and
 * provided buffer don't match and validation was requested, a BadHeader
 * exception object is thrown, and pipeline is aborted.
 */
class UnhashStreamLink: public Pipeline::InOutLink{
private:
    const std::array<uint8_t, 32> initBytes;
    const bool validate;

    Pipeline::Buffer::Ptr inBuffer;
	uint8_t* readingFrom;
	uint8_t* readingTo;
	uint8_t* writingTo;

    /** @brief Reads-in a buffer and sets internal data pointers.*/
    void readIn();
    /** @brief Writes out a buffer and sets internal data pointers.*/
    void writeOut();

    /** @brief Ovveride of Pipeline::InOutLink method. */
    void runThread() override;

public:

    /** @brief Exception class that is thrown by UnhashStreamLink if header
     * found in the input stream doesn't have the expected value.*/
    class BadHeader: public std::exception{
    public:
        /** @brief Returns a generic string explaining the situation leading to
         * BadHeader exception. */
        const char* what() const noexcept override{
            return "Incorrect hash-stream header.";
        }
    };

    /** @brief Initializes hash-stream link.
     * @param initBytes 32 bytes to be compared to the input stream header;
     * @param validate If false, input stream header validation is not
     *        performed.
     */
	inline UnhashStreamLink(const std::array<uint8_t,32>& initBytes, bool validate=true) noexcept
		:initBytes(initBytes),
		  validate(validate)
	{}
};

/** @brief Performs zLib deflate compression algorithm on pipeline data. */
class DeflateLink: public Pipeline::InOutLink{
private:
    int level;

    /** @brief Ovveride of Pipeline::InOutLink method. */
    std::size_t requestedMaxSize() noexcept override;

    /** @brief Ovveride of Pipeline::InOutLink method. */
    void runThread() override;

public:
    /** @brief Initializes DeflateLink object.
     * @param level Compression level (as specified by zLib).
     */
    inline DeflateLink(int level = 8) noexcept
        :level(level)
    {}
};

/** @brief Performs zLib inflate decompression algorithm on pipeline data. */
class InflateLink: public Pipeline::InOutLink{
private:
    /** @brief Ovveride of Pipeline::InOutLink method. */
    std::size_t requestedMaxSize() noexcept override;

    /** @brief Ovveride of Pipeline::InOutLink method. */
    void runThread() override;
};


}






#endif // LINKS_H
