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

//ToDo:: istream is inherently blocking. Is this a problem?
class IStreamLink: public Pipeline::OutLink{
private:

        std::unique_ptr<std::istream> ffile;
        std::string filename;

public:
        inline IStreamLink(std::string filename) noexcept
            :filename(std::move(filename))
        {}

        inline IStreamLink(std::unique_ptr<std::istream> file, std::string filename= std::string()) noexcept
                :ffile(std::move(file)),
                  filename(std::move(filename))
        {}

        ~IStreamLink(){
            ffile.release();
        }

        void runThread() override;

};

class OStreamLink: public Pipeline::InLink{
private:
        std::unique_ptr<std::ostream> ffile;
        std::string filename;
        std::promise<std::unique_ptr<std::ostream>> finished;
public:

        inline OStreamLink(std::string filename) noexcept
            :filename(std::move(filename))
        {}

        inline OStreamLink(std::unique_ptr<std::ostream> file, std::string filename= std::string()) noexcept
                :ffile(std::move(file)),
                  filename(std::move(filename))
        {}

        std::future<std::unique_ptr<std::ostream>> getFuture() noexcept{
            return finished.get_future();
        }

        void runThread() override;

};

class OStreamTeeLink: public Pipeline::InOutLink{
private:
        std::unique_ptr<std::ostream> ffile;
        std::string filename;

        void runThread() override;
public:
        inline OStreamTeeLink(std::string filename) noexcept
            :filename(std::move(filename))
        {}

        inline OStreamTeeLink(std::unique_ptr<std::ostream> file, std::string filename= std::string()) noexcept
                :ffile(std::move(file)),
                  filename(std::move(filename))
        {}



};

class EvpCipher: public Pipeline::InOutLink{
private:
    OSSL::EvpCipher cipher;

public:
    inline EvpCipher(OSSL::EvpCipher cipher) noexcept
        :cipher(std::move(cipher))
    {}

    inline OSSL::EvpCipher& context() noexcept{
        return cipher;
    }

    std::size_t requestedMaxSize() noexcept override;

    void runThread() override;

};

class HashStreamLink: public Pipeline::InOutLink{
private:
        const std::array<uint8_t, 32> initBytes;

        std::size_t requestedMaxSize() noexcept override;

        void runThread() override;
public:

        inline HashStreamLink(const std::array<uint8_t,32>& initBytes) noexcept
                :initBytes(initBytes)
        {}
};

class UnhashStreamLink: public Pipeline::InOutLink{
private:
    const std::array<uint8_t, 32> initBytes;
    const bool validate;

    Pipeline::Buffer::Ptr inBuffer;
	uint8_t* readingFrom;
	uint8_t* readingTo;
	uint8_t* writingTo;

    void readIn();
    void writeOut();

    void runThread() override;
public:

	inline UnhashStreamLink(const std::array<uint8_t,32>& initBytes, bool validate=true) noexcept
		:initBytes(initBytes),
		  validate(validate)
	{}
};

class DeflateLink: public Pipeline::InOutLink{
private:
    int level;

    std::size_t requestedMaxSize() noexcept override;
    void runThread() override;

public:
    inline DeflateLink(int level = 8) noexcept
        :level(level)
    {}
};

class InflateLink: public Pipeline::InOutLink{
private:
    std::size_t requestedMaxSize() noexcept override;

    void runThread() override;
};









#endif // LINKS_H
