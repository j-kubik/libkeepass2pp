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
#ifndef PIPELINE_H
#define PIPELINE_H

#include <array>
#include <vector>
#include <future>

#include "util.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <exception>
#include <atomic>
#include <array>

#include <libkeepass2pp/keepass2pp_config.h>

class Pipeline{
public:
    class InLink;
    class OutLink;
    class InOutLink;

private:

    class Link{
    private:
        static void runThreadFunc(std::unique_ptr<Link> link) noexcept;
        virtual void runThread()=0;

    protected:
        virtual void abort(std::exception_ptr e) noexcept;

    public:
        inline Link() noexcept
        {}

        virtual ~Link() noexcept;

        friend class Pipeline;
        friend class InLink;
    };

public:

    class Buffer{
    public:

        static constexpr std::size_t maxSize = KEEPASS2PP_PIPELINE_BUFFER_SIZE*1024 - sizeof(std::size_t);
        static constexpr unsigned int maxCount = 10;

    private:
        std::array<uint8_t, maxSize> farray;
        std::size_t fsize;

    public:

        // Default parameter value here sometimes causes trash to appear?
        inline Buffer(std::size_t size = maxSize) noexcept
            :fsize(size)
        {}

        inline void setSize(std::size_t size) noexcept{
#ifndef KEEPASS2PP_NDEBUG
            assert(size <= maxSize);
#endif
            fsize = size;
        }

        inline std::size_t size() const noexcept{
            return fsize;
        }

        inline const std::array<uint8_t, maxSize>& data() const noexcept{
            return farray;
        }

        inline std::array<uint8_t, maxSize>& data() noexcept{
            return farray;
        }

    };

    typedef std::unique_ptr<Buffer> BufferPtr;

    class InLink: virtual public Link{
    private:
        bool connected;
        std::queue<BufferPtr> queue;
        std::mutex queueMutex;
        std::condition_variable condition;
        std::exception_ptr exception;

        virtual void abort(std::exception_ptr e) noexcept override;

    protected:
        BufferPtr read();

        virtual void join(OutLink* link, std::size_t maxFill) noexcept;

    public:
        inline InLink() noexcept
            :connected(false)
        {}

        ~InLink() noexcept override;

        friend class Pipeline;
        friend class OutLink;
        friend class InOutLink;
    };

    class OutLink: virtual public Link{
    private:
        InLink* inLink;
        std::size_t fmaxFill;

        virtual void abort(std::exception_ptr e) noexcept override;
    public:

        OutLink() noexcept
            :inLink(nullptr)
        {}

        virtual ~OutLink() noexcept override;

    protected:

        inline std::size_t maxFill() const noexcept{
            return fmaxFill;
        }

        void write(BufferPtr ptr);

        void finish() noexcept;

        friend class Link;
        friend class InOutLink;
        friend class Pipeline;
    };

    class InOutLink: public InLink, public OutLink{
    private:
        virtual void abort(std::exception_ptr e) noexcept override;
    };

    Pipeline();

    void setStart(std::unique_ptr<OutLink> link) noexcept;

    void appendLink(std::unique_ptr<InOutLink> link);

    void setFinish(std::unique_ptr<InLink> link) noexcept;
    std::unique_ptr<InLink> takeFinish() noexcept;

    void run();

private:

    std::unique_ptr<InLink> finLink;
    std::unique_ptr<OutLink> foutLink;

    std::vector<std::unique_ptr<InOutLink>> links;

    friend class InLink;
    friend class OutLink;
    friend class Link;
};

#endif // PIPELINE_H
