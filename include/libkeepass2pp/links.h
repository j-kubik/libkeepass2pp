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

//ToDo:: Istream is inherently blocking. Is this a problem?
class IStreamLink: public Pipeline::OutLink{
private:

        std::unique_ptr<std::istream> ffile;

public:
        IStreamLink(const std::string& filename) noexcept;

        inline IStreamLink(std::unique_ptr<std::istream> file) noexcept
                :ffile(std::move(file))
        {}

        ~IStreamLink(){
            ffile.release();
        }

        virtual void runThread() override;

};

class OStreamLink: public Pipeline::InLink{
private:
        std::unique_ptr<std::ostream> ffile;
        std::promise<void> finished;
public:

        OStreamLink(const std::string& filename) noexcept;

        inline OStreamLink(std::unique_ptr<std::ostream> file) noexcept
                :ffile(std::move(file))
        {}

        std::future<void> getFuture() noexcept{
            return finished.get_future();
        }

        virtual void runThread() override;

};

class OStreamTeeLink: public Pipeline::InOutLink{
private:
        std::unique_ptr<std::ostream> ffile;
public:
        OStreamTeeLink(const std::string& filename) noexcept;

        inline OStreamTeeLink(std::unique_ptr<std::ostream> file) noexcept
                :ffile(std::move(file))
        {}

        virtual void runThread() override;

};

class EvpCipher: public Pipeline::InOutLink{
private:
    OSSL::EvpCipherCtx ctx;

public:
    inline EvpCipher() noexcept
    {}

    inline OSSL::EvpCipherCtx& context() noexcept{
        return ctx;
    }

    virtual void join(Pipeline::OutLink* link, std::size_t maxFill) noexcept override;

    virtual void runThread() override;

};

class HashStreamLink: public Pipeline::InOutLink{
private:
        const std::array<uint8_t, 32> initBytes;
public:

        inline HashStreamLink(const std::array<uint8_t,32>& initBytes) noexcept
                :initBytes(initBytes)
        {}

        virtual void join(Pipeline::OutLink* link, std::size_t maxFill) noexcept override;

        virtual void runThread() override;
};

class UnhashStreamLink: public Pipeline::InOutLink{
private:
	const std::array<uint8_t, 32> initBytes;
	const bool validate;

    Pipeline::BufferPtr inBuffer;
	uint8_t* readingFrom;
	uint8_t* readingTo;
	uint8_t* writingTo;

	void readIn();
	void writeOut();

public:

	inline UnhashStreamLink(const std::array<uint8_t,32>& initBytes, bool validate=true) noexcept
		:initBytes(initBytes),
		  validate(validate)
	{}

	virtual void runThread() override;
};

class DeflateLink: public Pipeline::InOutLink{
private:
    int level;

public:
    inline DeflateLink(int level = 8) noexcept
        :level(level)
    {}

    virtual void join(Pipeline::OutLink* link, std::size_t maxFill) noexcept override;

    virtual void runThread() override;
};

class InflateLink: public Pipeline::InOutLink{
public:
    virtual void join(Pipeline::OutLink* link, std::size_t maxFill) noexcept override;

    virtual void runThread() override;
};









#endif // LINKS_H
