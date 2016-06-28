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
#include <system_error>
#include <numeric>
#include <cassert>

#include "../include/libkeepass2pp/keepass2pp_config.h"
#include "../include/libkeepass2pp/pipeline.h"
#include "../include/libkeepass2pp/util.h"

void Pipeline::Link::runThreadFunc(Link::Ptr link) noexcept{
    try{
        link->runThread();
    }catch(...){
        link->abort(std::current_exception());
    }
}

void Pipeline::Link::abort(std::exception_ptr) noexcept{}

Pipeline::Link::~Link() noexcept{}

//-----------------------------------------------------------------------------

// InLink valid states
/*
 * 1. !connected && queue.size() == 0 && exception == 0; // disconnected.
 * 2. connected && queue.size() == 0 && exception == 0; // waiting for write.
 * 3. connected && queue.size() == maxCount && exception == 0; // waiting for read.
 * 4. connected && queue.size() < maxCount  && queue.size() > 0 && exception == 0; // processing (no wait).
 * 5. connected && queue.size() == 0 && exception != 0; // backwards error.
 * 6. !connected && queue.size() == 0 && exception != 0; // forwards error.
 */

/* State changes:
 * 1. invalid
 * 2.
 */
void Pipeline::InLink::abort(std::exception_ptr e) noexcept{
    Link::abort(e);

    std::unique_lock<std::mutex> lock(queueMutex);

    if (exception)
        return;

    exception = std::move(e);

    std::queue<Buffer::Ptr> tmp;
    using std::swap;
    swap(tmp, queue);

    lock.unlock();
    condition.notify_one();
}

Pipeline::Buffer::Ptr Pipeline::InLink::read(){
    std::unique_lock<std::mutex> lock(queueMutex);

    // The condition for exception is probably not necesary.
    condition.wait(lock, [this]{ return queue.size() > 0 || !connected || exception; });

    if (exception)
        std::rethrow_exception(exception);

    std::size_t queueSize = queue.size();
    if (queueSize){
        Buffer::Ptr result = std::move(queue.front());
        queue.pop();
        lock.unlock();

        if (queueSize == Buffer::maxCount)
            condition.notify_one();
        return result;
    }
    return Buffer::Ptr();
}

void Pipeline::InLink::join(OutLink* link) noexcept{
    assert(connected == false);
    assert(link);
    assert(link->inLink == nullptr);
    link->inLink = this;
    connected = true;
    link->fmaxSize = requestedMaxSize();
}


Pipeline::InLink::~InLink() noexcept{
    // Wait until other end gets disconnected, so we can safely destroy.
    std::unique_lock<std::mutex> lock(queueMutex);
    condition.wait(lock, [this]{ return !connected; });
}

//-----------------------------------------------------------------------------

Pipeline::OutLink::~OutLink() noexcept{
    if (inLink){
        finish();
    }
}

void Pipeline::OutLink::abort(std::exception_ptr e) noexcept{
    Link::abort(e);
    if (!inLink)
        return;

    std::unique_lock<std::mutex> lock(inLink->queueMutex);
    assert(inLink->connected == true);
    if (!inLink->exception)
        inLink->exception = std::move(e);
    inLink->connected = false;
    InLink* tmp = inLink;
    inLink = nullptr;

    tmp->condition.notify_one();
    lock.unlock();
}

void Pipeline::OutLink::write(Buffer::Ptr ptr){
    assert(inLink);
    std::unique_lock<std::mutex> lock(inLink->queueMutex);
    assert(inLink->connected == true);

    inLink->condition.wait(lock, [this]{ return inLink->queue.size() < Buffer::maxCount; });

    if (inLink->exception)
        std::rethrow_exception(inLink->exception);


    std::size_t queueSize = inLink->queue.size();
    inLink->queue.push(std::move(ptr));
    lock.unlock();
    if (queueSize == 0)
            inLink->condition.notify_one();
}

void Pipeline::OutLink::finish() noexcept{
    assert(inLink);
    std::unique_lock<std::mutex> lock(inLink->queueMutex);
    assert(inLink->connected == true);
    inLink->connected = false;
    inLink->condition.notify_one();
    lock.unlock();
    inLink = nullptr;
}

//--------------------------------------------------------------------------------

void Pipeline::InOutLink::abort(std::exception_ptr e) noexcept{
        InLink::abort(e);
        OutLink::abort(std::move(e));
}

//--------------------------------------------------------------------------------

void Pipeline::setStart(OutLink::Ptr link) noexcept{
	//ToDo: should I disallow circular pipelines?
	assert(foutLink == 0); //Multiple start links for a pipeline.

	foutLink = std::move(link);
}

void Pipeline::appendLink(InOutLink::Ptr link){
	links.push_back(std::move(link));
}

void Pipeline::setFinish(InLink::Ptr link) noexcept{
	assert(finLink == 0); // multiple finish links for a pipeline.

	finLink = std::move(link);
}

void Pipeline::run(){

    assert(finLink);
    assert(foutLink);

    InLink* endLink = finLink.get();
    for (std::vector<InOutLink::Ptr>::reverse_iterator I = links.rbegin();
         I != links.rend(); I++){
        endLink->join(I->get());
        endLink = I->get();
    }

    endLink->join(foutLink.get());

    std::thread(&Link::runThreadFunc,std::move(finLink)).detach();
    for (InOutLink::Ptr& link: links){
        std::thread(&Link::runThreadFunc, std::move(link)).detach();
    }
    std::thread(&Link::runThreadFunc, std::move(foutLink)).detach();

    finLink = InLink::Ptr();
    foutLink = OutLink::Ptr();
    links.clear();
}


//-------------------------------------------------------------------------------






