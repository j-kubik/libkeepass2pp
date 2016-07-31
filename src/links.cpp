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
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cassert>

#include <openssl/err.h>
// ToDo: remove and use wrappers around Digest.
#include <openssl/sha.h>

#include <zlib.h>

#include "../include/libkeepass2pp/wrappers.h"
#include "../include/libkeepass2pp/links.h"

using namespace Kdbx;

void IStreamLink::runThread(){
    if (!ffile){
        std::unique_ptr<std::ifstream> file(new std::ifstream());
        file->exceptions(std::istream::badbit);
        file->open(filename);
        ffile = std::move(file);
    }else{
        ffile->exceptions(std::istream::badbit);
    }

    Pipeline::Buffer::Ptr buffer;
    while (*ffile){
        buffer = Pipeline::Buffer::Ptr(new Pipeline::Buffer());
        ffile->read(reinterpret_cast<char*>(buffer->data().data()), maxSize());
        if (!ffile->gcount()){
            break;
        }
        buffer->setSize(ffile->gcount());
        write(std::move(buffer));
    }

    finish();
}

//------------------------------------------------------------------------------------

void OStreamLink::runThread(){
    try{
        if (!ffile){
            std::unique_ptr<std::ofstream> file(new std::ofstream());
            file->exceptions(std::ostream::badbit);
            file->open(filename);
            ffile = std::move(file);
        }else{
            ffile->exceptions(std::ostream::badbit);
        }

        Pipeline::Buffer::Ptr inBuffer;
        while ((inBuffer = read())){
            ffile->write(reinterpret_cast<const char*>(inBuffer->data().data()), inBuffer->size());
        }
        ffile->flush();
        finished.set_value(std::move(ffile));
    }catch(...){
        ffile->flush();
        finished.set_value(std::move(ffile));
        throw;
    }
}

//------------------------------------------------------------------------------------

void OStreamTeeLink::runThread(){
    if (!ffile){
        std::unique_ptr<std::ofstream> file(new std::ofstream());
        file->exceptions(std::ostream::badbit);
        file->open(filename);
        ffile = std::move(file);
    }else{
        ffile->exceptions(std::ostream::badbit);
    }

    Pipeline::Buffer::Ptr inBuffer;
    while ((inBuffer = read())){
        ffile->write(reinterpret_cast<const char*>(inBuffer->data().data()), inBuffer->size());
        write(std::move(inBuffer));
    }
    ffile->flush();
    finish();
}

//------------------------------------------------------------------------------------

std::size_t EvpCipher::requestedMaxSize() noexcept{
    std::size_t mSize = maxSize();
    if (cipher.block_size() > 0)
        mSize -= cipher.block_size();

    return mSize;
}

#ifndef NDEBUG
namespace {

class LoadSSLCryptoStrings{
public:
LoadSSLCryptoStrings(){
    ERR_load_crypto_strings();
}
};

LoadSSLCryptoStrings l;

}
#endif

void EvpCipher::runThread(){
    Pipeline::Buffer::Ptr inBuffer;
    Pipeline::Buffer::Ptr outBuffer(new Pipeline::Buffer());

    while ((inBuffer = read())){
            assert(inBuffer->size() + cipher.block_size() <= maxSize());

            std::size_t outSize = cipher.update(outBuffer->data().data(), inBuffer->data().data(), inBuffer->size());

            assert(std::size_t(outSize) < maxSize());
            outBuffer->setSize(outSize);

            write(std::move(outBuffer));
            using std::swap;
            swap(outBuffer, inBuffer);
    }

    std::size_t outSize = cipher.final(outBuffer->data().data());
    if (outSize){
            outBuffer->setSize(outSize);
            write(std::move(outBuffer));
    }

    finish();

}

//-------------------------------------------------------------------------------------

std::size_t HashStreamLink::requestedMaxSize() noexcept{
    return Pipeline::Buffer::maxSize;
}

void HashStreamLink::runThread(){

    Pipeline::Buffer::Ptr outBuffer(new Pipeline::Buffer());
    std::copy(initBytes.begin(), initBytes.end(), outBuffer->data().begin());
    outBuffer->setSize(initBytes.size());
    write(std::move(outBuffer));

    uint32_t blockIndex = 0;

    Pipeline::Buffer::Ptr inBuffer;
    uint8_t* readAt = nullptr;
    uint8_t* readEnd = nullptr;

    outBuffer = Pipeline::Buffer::Ptr(new Pipeline::Buffer(maxSize()));
    uint8_t* writeAt = (outBuffer->data().data() + 40);
    uint8_t* writeEnd = (outBuffer->data().data() + maxSize());
    do{

        if (readAt == readEnd){
            inBuffer = read();
            if (!inBuffer)
                break;

            readAt = inBuffer->data().data();
            readEnd = readAt + inBuffer->size();
        }
        std::size_t toCopy = std::min(writeEnd - writeAt, readEnd - readAt);
        writeAt = std::copy_n(readAt, toCopy, writeAt);
        readAt += toCopy;

        if (writeAt == writeEnd){
            OSSL::Digest d(EVP_sha256());
            d.update(outBuffer->data().data() + 40, outBuffer->size() - 40);
            d.final(outBuffer->data().data() + 4);

            toLittleEndian<uint32_t>(outBuffer->size() - 40, outBuffer->data().data() + 36);
            toLittleEndian<uint32_t>(blockIndex, outBuffer->data().data());
            ++ blockIndex;

            write(std::move(outBuffer));
            outBuffer = Pipeline::Buffer::Ptr(new Pipeline::Buffer(maxSize()));
            writeAt = (outBuffer->data().data() + 40);
            writeEnd = (outBuffer->data().data() + maxSize());
        }


    }while(true);

    if (writeAt != outBuffer->data().data() + 40){

        OSSL::Digest d(EVP_sha256());
        int lastSize = writeAt - outBuffer->data().data();
         d.update(outBuffer->data().data() + 40, lastSize - 40);
        d.final(outBuffer->data().data() + 4);

        toLittleEndian<uint32_t>(lastSize - 40, outBuffer->data().data() + 36);
        toLittleEndian<uint32_t>(blockIndex, outBuffer->data().data());
        blockIndex++;
        outBuffer->setSize(lastSize);
        write(std::move(outBuffer));
    }

    outBuffer = Pipeline::Buffer::Ptr(new Pipeline::Buffer(40));
    toLittleEndian<uint32_t>(blockIndex, outBuffer->data().data());
    std::fill(outBuffer->data().begin() + 4,outBuffer->data().begin()+40, 0);
    write(std::move(outBuffer));


    finish();
}

//-------------------------------------------------------------------------------------

void UnhashStreamLink::readIn(){
    if (!(inBuffer = read()))
        throw std::runtime_error("Unexpected end of stream.");

    readingFrom = inBuffer->data().data();
    readingTo = inBuffer->data().data() + inBuffer->size();
    writingTo = readingFrom;
}

void UnhashStreamLink::writeOut(){
    if (writingTo > inBuffer->data().data()){
        inBuffer->setSize(writingTo-inBuffer->data().data());
        write(std::move(inBuffer));
    }
}

void UnhashStreamLink::runThread(){

    uint32_t blockIndex = 0;

    std::size_t chunkSize;

    //ToDo: base init bytes size on provided data...
    {
        std::array<uint8_t, 32> encryptedInitBytes;
        std::size_t initBytesRead = 0;

        while (initBytesRead < 32){
            readIn();
            chunkSize = std::min(std::size_t(readingTo - readingFrom), 32 - initBytesRead);
            std::copy(readingFrom,
                      readingFrom + chunkSize,
                      encryptedInitBytes.begin() + initBytesRead);

            initBytesRead += chunkSize;
            readingFrom += chunkSize;
        }

        auto match = std::mismatch(encryptedInitBytes.begin(), encryptedInitBytes.end(), initBytes.begin());
        if (match != std::make_pair(encryptedInitBytes.end(), initBytes.end())){
            throw BadHeader();
        }

    }

    std::size_t blockSize;

    do{

        std::size_t headerRead = 0;
        uint8_t rawHeader[40];

        do{
            if (readingTo == readingFrom){
                writeOut();
                readIn();
            }

            chunkSize = std::min(std::size_t(readingTo - readingFrom), 40 - headerRead);
            std::copy(readingFrom,  readingFrom + chunkSize,
                      &rawHeader[headerRead]);
            headerRead += chunkSize;
            readingFrom += chunkSize;

        }while(headerRead < 40);

        if (fromLittleEndian<uint32_t>(&rawHeader[0]) != blockIndex)
            throw std::runtime_error("Stream data corrupted.");
        blockIndex++;

        blockSize = fromLittleEndian<uint32_t>(&rawHeader[36]);

        if (blockSize == 0){
            if (std::any_of(&rawHeader[4], &rawHeader[36], [](uint8_t value)->bool{ return value != 0; }))
                throw std::runtime_error("Stream data corrupted.");
            break;
        }

        OSSL::Digest d(EVP_sha256());
        std::size_t blockRead = 0;

        while (blockRead < blockSize){
            chunkSize = std::min(std::size_t(readingTo - readingFrom), blockSize-blockRead);
            d.update(readingFrom, chunkSize);

            if (readingFrom > writingTo)
                std::copy(readingFrom, readingFrom + chunkSize, writingTo);
            readingFrom += chunkSize;
            writingTo += chunkSize;
            blockRead += chunkSize;

            if (readingFrom == readingTo){
                writeOut();
                readIn();
            }
        }
        std::array<uint8_t, 32> dataHash;
        d.final(dataHash);

        if (!std::equal(dataHash.begin(), dataHash.end(), &rawHeader[4]))
            throw std::runtime_error("Stream data corrupted.");

    }while(true);

    writeOut();
    finish();

}

//-------------------------------------------------------------------------------------

std::size_t DeflateLink::requestedMaxSize() noexcept{
    return Pipeline::Buffer::maxSize;
}

void DeflateLink::runThread(){

    Pipeline::Buffer::Ptr inBuffer;
    Pipeline::Buffer::Ptr outBuffer(new Pipeline::Buffer(maxSize()));

    // ToDo: add allocation functions for safe processing.

    Zlib::Deflater strm(level, MAX_WBITS | 16);
    strm->next_out = outBuffer->data().data();
    strm->avail_out = outBuffer->size();
    strm->avail_in = 0;

    int ret;
    while (true){

        if (strm->avail_in == 0){
            inBuffer = read();
            if (!inBuffer)
                break;

            strm->next_in = inBuffer->data().data();
            strm->avail_in = inBuffer->size();
        }

        if (strm->avail_out == 0){
            write(std::move(outBuffer));
            outBuffer = Pipeline::Buffer::Ptr(new Pipeline::Buffer(maxSize()));
            strm->next_out = outBuffer->data().data();
            strm->avail_out = outBuffer->size();
        }

        ret = deflate(strm, Z_NO_FLUSH);
        assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
    };

    do{
        if (strm->avail_out == 0){
            write(std::move(outBuffer));
            outBuffer = Pipeline::Buffer::Ptr(new Pipeline::Buffer(maxSize()));
            strm->next_out = outBuffer->data().data();
            strm->avail_out = outBuffer->size();
        }
        ret = deflate(strm, Z_FINISH);
    }while(ret == Z_OK);
    assert(ret == Z_STREAM_END);

    if (strm->avail_out < maxSize() &&
        strm->avail_out != outBuffer->size()){
        outBuffer->setSize(outBuffer->size() - strm->avail_out);
        write(std::move(outBuffer));
    }

    deflateEnd(strm);
    finish();
}

//-------------------------------------------------------------------------------------

std::size_t InflateLink::requestedMaxSize() noexcept{
    return Pipeline::Buffer::maxSize;
}

void InflateLink::runThread(){

        Pipeline::Buffer::Ptr inBuffer;
        Pipeline::Buffer::Ptr outBuffer;

    Zlib::Inflater strm(MAX_WBITS | 16);

    outBuffer = Pipeline::Buffer::Ptr(new Pipeline::Buffer());
    strm->next_out = outBuffer->data().data();
    strm->avail_out = outBuffer->size();

    inBuffer = read();
    strm->next_in = inBuffer->data().data();
    strm->avail_in = inBuffer->size();

    int ret;
    do{

        if (strm->avail_in == 0){
            inBuffer = read();
            if (!inBuffer)
                throw std::runtime_error("Unexpected end of stream.");
            strm->next_in = inBuffer->data().data();
            strm->avail_in = inBuffer->size();
        }

        if (strm->avail_out == 0){

            write(std::move(outBuffer));
            outBuffer = Pipeline::Buffer::Ptr(new Pipeline::Buffer());
            outBuffer->setSize(maxSize());

            strm->next_out = outBuffer->data().data();
            strm->avail_out = maxSize();
		}

		ret = inflate(strm, Z_NO_FLUSH);
		assert(ret != Z_STREAM_ERROR);  /* state not clobbered */

		switch (ret) {
		case Z_STREAM_END:
		case Z_BUF_ERROR:
		case Z_OK:
			break;

		case Z_NEED_DICT:
			ret = Z_DATA_ERROR;     /* and fall through */
			//			case Z_DATA_ERROR:
			//			case Z_MEM_ERROR:
		default:
            Zlib::Inflater::throwError("Error decompressing the data.", ret, strm->msg);
        }

    }while (ret != Z_STREAM_END);

    assert(!read());

    if (strm->avail_out < maxSize()){
        outBuffer->setSize(maxSize() - strm->avail_out);
        write(std::move(outBuffer));
    }

    finish();
}


//-------------------------------------------------------------------------------------



