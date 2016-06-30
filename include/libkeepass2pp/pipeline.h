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

/** @brief Pipeline is a class that connects and starts a multi-threaded data
 *         processing pipline.
 *
 * Each pipeline consists of a linear chain of links. It starts with an OutLink
 * object (data producer), ends with InLink object (data consumer), and has any
 * number of InOutLink objects (data processors) in between. Each link runs it's
 * runThread() method in a separate thread. Links are comunicating by sending
 * (in case of OutLink) and receiving (in case of InLink) fixed size buffers using
 * \p write() and \p read() methods respectively. Processing follows until all links
 * exit their runThread() method.
 *
 * Pipeline doesn't provide any mechanism that allows comunication between links
 * and external code, it doesn't even inform if it is still active or not.
 * @note This is a design decision dictated by the fact that there is no single
 *       condition to wait for in such case. Some programs might be only interested
 *       in tracking progress of a single link - ie. pipeline saving internal data
 *       structures into a file will probably want to be notified as soon as those
 *       structurres are not used by pipeline.
 */
class Pipeline{
public:
    class InLink;
    class OutLink;
    class InOutLink;

private:

    /** @brief Base class for all pipeline links.
     *
     * Implementations of link classes should not derive from this class directly.
     * Instead they should use InLink, OutLink or InOutLink.
     */
    class Link{
    private:
        /** @brief Owning pointer to Link object. */
        typedef std::unique_ptr<Link> Ptr;

        /** @brief Main function running pipeline's thread.
         * @param link Owning pointer to a link object. Link is always destroyed when
         *        it's thread finishes.
         *
         * It calls runThread, and if throws an exception, it calls abort() with a
         * pointer to that exception.
         */
        static void runThreadFunc(Link::Ptr link) noexcept;

        /** @brief Link's processing function.
         *
         * Link implementers should re-implement this function with code that processes
         * pipeline data. This method is always run in it's own thread.
         *
         * If this method returns with an exception, pipeline's processing is aborted.
         * This is preffered method of aborting execution.
         */
        virtual void runThread()=0;

        /** @brief Aborts execution of a pipeline. */
        virtual void abort(std::exception_ptr e) noexcept;

    public:
        
        virtual ~Link() noexcept;

        friend class Pipeline;
        friend class InLink;
        friend class OutLink;
    };

public:

    /** @brief Buffer class represents constant-size data buffer that is passed between
     *         links.
     * 
     * Buffers have fixed maximum-size but using setSize() and size() members links can
     * comunicate how much data in the buffer is to be considered significant. The data
     * buffer should be considered valid only to size() bytes from start. Any bytes
     * after size() bytes are not part of pipeline stream.
     */
    class Buffer{
    public:

        /** @brief Owning pointer to Buffer object. */
        typedef std::unique_ptr<Buffer> Ptr;

        /** @brief Size of a Buffer structure.
         *
         * Currently this value can be configured while building the library and
         * it defaults to 4kB, so that entire buffer fits into typical memory
         * page.*/
        static constexpr std::size_t overallSize = KEEPASS2PP_PIPELINE_BUFFER_SIZE*1024;

        /** @brief Maximal size of a data buffer.
         *
         * This is the siez of entire structure minus space necesary for size
         * field.
         */
        static constexpr std::size_t maxSize = (overallSize - sizeof(std::size_t))/alignof(std::size_t)*alignof(std::size_t);

        /** @brief Maximal number of unprocessed buffers that can wait in queue
         *         between two links.
         *
         * This value is somewhat arbitrary. Future versions will probably
         * include a mechanism to override it either while building the library
         * or directly by library user.
         */
        static constexpr unsigned int maxCount = 10;

    private:
        std::array<uint8_t, maxSize> farray;
        std::size_t fsize;

    public:

        /** @brief Constructs a buffer and sets it's size.
         *
         * The buffer data remains uninitialized.
         */
        inline Buffer(std::size_t size = maxSize) noexcept
            :fsize(size)
        {}
        
        /** @brief Sets the buffer size to a specific value.
         *
         * Buffer size is only an additioanl information. Setting this value
         * does not influence data contained in the buffer itself in any way.
         */
        inline void setSize(std::size_t size) noexcept{
#ifndef KEEPASS2PP_NDEBUG
            assert(size <= maxSize);
#endif
            fsize = size;
        }

        /** @brief Returns last set buffer size */
        inline std::size_t size() const noexcept{
            return fsize;
        }

        /** @brief Returns a reference to data buffer. */
        inline const std::array<uint8_t, maxSize>& data() const noexcept{
            return farray;
        }

        /** @brief Returns a reference to data buffer. */
        inline std::array<uint8_t, maxSize>& data() noexcept{
            return farray;
        }

    };

    /** @brief Data consumer link.
     *
     * Base class for data consumer links. InLink derived classes use read()
     * method in order to retrieve data from data producer link.
     */
    class InLink: virtual public Link{
    private:
        bool connected;  //! \p true if it has a OutLink connected.
        std::queue<Buffer::Ptr> queue; //! Data buffer queue
        std::mutex queueMutex;  //! Mutex protecting the data queue
        std::condition_variable condition; //! To wait on queue full/empty
        std::exception_ptr exception; //! If aborted, it contains pointer
                                      //! to an exception. Otherwise nullptr.

        /** @brief Aborts execution of a pipeline. */
        virtual void abort(std::exception_ptr e) noexcept override;

        /** @brief Connects this link with an OutLink object.
         * @param link OutLink object to connect to.
         */
        void join(OutLink* link) noexcept;
    protected:
        /** @brief Returns next Buffer sent by OutLink.
         *
         * If data producer has no more data to send, returns nullptr.
         * If pipeline is being aborted by any link - independent if it is
         * up or down the pipeline - this method throws an exception that caused
         * the pipeline to abort.
         *
         * This method might block until data producer sends a buffer.
         */
        Buffer::Ptr read();

        /** @brief Returns maximal size of input buffer data that this link
         *         wants to accept.
         *
         * This method is called only once for a link from the thread that
         * called Pipeline::run() on pipeline owning that link.
         *
         * Some links operate on data without changing it's length or changing
         * it in a predictable manner. Those links can reimplement this
         * function to inform data sender that it should send at most maxSize
         * bytes per buffer. Data producers are required to comply witch such a
         * wish, thus enabling data consumers to process the data in-place
         * without theneed to allocate additional buffers.
         *
         * Default implementation returns Buffer::maxSize, ie. requests fully
         * filled buffers.
         */
        virtual inline std::size_t requestedMaxSize() noexcept{
            return Buffer::maxSize;
        }

    public:

        /** @brief Owning pointer to InLink object. */
        typedef std::unique_ptr<InLink> Ptr;

        inline InLink() noexcept
            :connected(false)
        {}

        ~InLink() noexcept override;

        friend class Pipeline;
        friend class OutLink;
        friend class InOutLink;
    };

    /** @brief Data producer link.
     *
     * Base class for data producer links. OutLink derived classes use write()
     * method in order to send data to data producer link.
     */
    class OutLink: virtual public Link{
    private:
        InLink* inLink;
        std::size_t fmaxSize;

        /** @brief Aborts execution of a pipeline. */
        virtual void abort(std::exception_ptr e) noexcept override;
    public:

        /** @brief Owning pointer to OutLink object. */
        typedef std::unique_ptr<OutLink> Ptr;

        inline OutLink() noexcept
            :inLink(nullptr)
        {}

        virtual ~OutLink() noexcept override;

    protected:

        /** @brief Maximum size of data that can be sent in a single Buffer
         *         object.
         *
         * This value is provided by data consumer connected to this link.
         * OutLink implementations should never send more data per Buffer
         * object.
         */
        inline std::size_t maxSize() const noexcept{
            return fmaxSize;
        }

        /** @brief Sends a buffer to the data consumer.
         *
         * If pipeline is being aborted by any link - independent if it is
         * up or down the pipeline - this method throws an exception that caused
         * the pipeline to abort.
         * This method might block if data consumers buffer input queue is full.
         */
        void write(Buffer::Ptr ptr);

        /** @brief Finishes data buffers sending.
         *
         * OutLink implementation might call this method inside runThread method
         * in order to indicate that no further data will be sent. Calling
         * write() or finish() after this call produces unknown behavior.
         */
        void finish() noexcept;

        friend class Link;
        friend class InOutLink;
        friend class Pipeline;
    };


    class InOutLink: public InLink, public OutLink{
    private:
        /** @brief Aborts execution of a pipeline. */
        virtual void abort(std::exception_ptr e) noexcept override final;

    protected:
        /** @brief Override of InLink::requestedMaxSize
         *
         * For InOutLink default return value is the result of
         * OutLink::maxSize(). Links are connected backwards, so when this
         * method is called, maxSize called for this object reports a valid
         * value.
         */
        virtual inline std::size_t requestedMaxSize() noexcept{
            return maxSize();
        }

    public:
        /** @brief Owning pointer to InOutLink object. */
        typedef std::unique_ptr<InOutLink> Ptr;
    };


    /** @brief Sets a start link for a pipeline.
     *
     * Currently van only be called once before Pipeline::run.
     */
    void setStart(OutLink::Ptr link) noexcept;

    /** Appends a link to the pipeline*/
    void appendLink(InOutLink::Ptr link);

    /** Sets a last link for a pipeline.
     *
     * Currently van only be called once before Pipeline::run.
     */
    void setFinish(InLink::Ptr link) noexcept;

    /** @breif Starts a pipeline.
     *
     * Connects all links in ent to begin order, and starts pipeline.
     *
     * After this call pipeline doesn't retain any link to the pipeline it
     * started; it is in default-constructed state and can be used to start
     * another pipeline.
     */
    void run();

private:

    InLink::Ptr finLink;
    OutLink::Ptr foutLink;

    std::vector<InOutLink::Ptr> links;

    friend class InLink;
    friend class OutLink;
    friend class Link;
};

#endif // PIPELINE_H
