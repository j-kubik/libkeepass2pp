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
#ifndef WRAPPERS_H
#define WRAPPERS_H

#include "libkeepass2pp/keepass2pp_config.h"
#include "util.h"

#include <string>
#include <memory>
#include <exception>
#include <iostream>
#include <cstring>
#include <vector>

#define ZLIB_CONST
#include <zlib.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <libxml/xmlerror.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>

namespace OSSL{

class exception: public std::runtime_error{
public:
    struct Error{
        unsigned long code;
        int line;
        int flags;
        std::string file;
        std::string data;
    };

    const std::vector<Error> errors;

    inline exception() noexcept
        :exception(getErrors())
    {}

    static void clearErrors();

private:
    static std::vector<Error> getErrors() noexcept;
    static std::string getMessage(const std::vector<Error>& errors) noexcept;

    inline exception(std::vector<Error> errors) noexcept
        :runtime_error(getMessage(errors)),
          errors(std::move(errors))
    {}
};

class Digest{
private:
    EVP_MD_CTX* ctx;
public:
    inline Digest() noexcept
        :ctx(nullptr)
    {}

    Digest(const EVP_MD* type, ENGINE* impl=nullptr);
    Digest(const Digest& d);

    inline Digest(Digest&& d) noexcept
        :ctx(d.ctx){
        d.ctx = nullptr;
    }

    ~Digest();

    Digest& operator=(const Digest& d);

    Digest& operator=(Digest d) noexcept{
        swap(*this, d);
        return *this;
    }

    inline explicit operator EVP_MD_CTX*() const noexcept{
        return ctx;
    }

    inline explicit operator bool() const noexcept{
        return ctx;
    }

    inline std::size_t size() const noexcept{
        return EVP_MD_CTX_size(ctx);
    }

    inline std::size_t block_size() const noexcept{
        return EVP_MD_CTX_block_size(ctx);
    }

    inline int type() const noexcept{
        return EVP_MD_CTX_type(ctx);
    }

    inline const EVP_MD* md() const noexcept{
        return EVP_MD_CTX_md(ctx);
    }

    void init(const EVP_MD *type = nullptr, ENGINE *impl = nullptr);

    void update(const uint8_t* data, std::size_t size);

    void update(const char* data, std::size_t size){
        update(reinterpret_cast<const uint8_t*>(data), size);
    }

    void update(const std::vector<uint8_t>& data, std::size_t size){
        update(data.data(), size);
    }

    void update(const std::vector<uint8_t>& data){
        update(data.data(), data.size());
    }

    void update(const SafeVector<uint8_t>& data, std::size_t size){
        update(data.data(), size);
    }

    void update(const SafeVector<uint8_t>& data){
        update(data.data(), data.size());
    }

    template <std::size_t s>
    void update(const std::array<uint8_t, s>& data){
        update(data.data(), s);
    }

    unsigned int final(uint8_t* data);
    void final(SafeVector<uint8_t>& data);

    std::vector<uint8_t> final();
    SafeVector<uint8_t> safeFinal();

    template <std::size_t s>
    void final(std::array<uint8_t, s>& result){
        assert(size() == s);
        unsigned int written;
        if (EVP_DigestFinal_ex(ctx, result.data(), &written)!=1)
            throw exception();

        unused(written);
        assert(written == s);
    }

    friend inline void swap(Digest& d1, Digest& d2) noexcept{
        using std::swap;
        swap(d1, d2);
    }

};


class EvpCipherCtx{
private:
    EVP_CIPHER_CTX ctx;

public:
    inline EvpCipherCtx() noexcept{
        EVP_CIPHER_CTX_init(&ctx);
    }

    inline ~EvpCipherCtx() noexcept{
        EVP_CIPHER_CTX_cleanup(&ctx);
    }

    inline operator EVP_CIPHER_CTX*() noexcept{
        return &ctx;
    }

    EvpCipherCtx(const EvpCipherCtx&) = delete;
    EvpCipherCtx(EvpCipherCtx&&) = delete;
    EvpCipherCtx& operator=(const EvpCipherCtx&) = delete;
    EvpCipherCtx& operator=(EvpCipherCtx&&) = delete;
};

inline void rand(uint8_t* data, std::size_t size){
    if (RAND_bytes(data, size) != 1)
        throw exception();
}

template <typename T, typename = typename std::enable_if<
              std::is_same<
                  typename std::remove_volatile<
                      decltype(std::declval<T>().data())>::type,
                  uint8_t*>::value
              >::type>
inline void rand(T& container, std::size_t size){
    rand(container.data(), size);
}

template <typename T, typename = typename std::enable_if<
              std::is_same<
                  typename std::remove_volatile<
                      decltype(std::declval<T>().data())>::type,
                  uint8_t*>::value
              >::type>
inline void rand(T& container){
    rand(container.data(), container.size());
}

template <typename T, typename ...Args, typename = typename std::enable_if<
              std::is_same<
                  typename std::remove_volatile<
                      decltype(std::declval<T>().data())
                      >::type,
                  uint8_t*>::value &&
              std::is_same<
                  typename std::remove_volatile<
                      decltype(std::declval<T>().size())
                      >::type,
                  std::size_t>::value
              >::type>
inline T rand(Args&& ...args){
    T result(args...);
    rand(result);
    return result;
}

}

//------------------------------------------------------------------------------

namespace XML{

#ifdef KEEPASS2PP_VERBOSE_XML_ERRORS
const char* toString(xmlErrorLevel domain) noexcept;
const char* toString(xmlErrorDomain domain) noexcept;
const char* toString(xmlParserErrors parserError) noexcept;
const char* toString(xmlReaderTypes readerType) noexcept;
#else
template <typename T>
const char* toString(T t) noexcept{
	static_assert(false, "This function is not available if keepass2pp is compiled "
						 "without verbose xml support. Use KEEPASS2PP_VERBOSE_XML_ERRORS "
						 "to determine support status." );
	return false;
}
#endif

class Error{
private:
	xmlError error;

public:

	inline Error() noexcept{
		memset(&error, 0, sizeof(xmlError));
	}

	inline Error(xmlError* err) noexcept{
		memset(&error, 0, sizeof(xmlError));
		xmlCopyError(err, &error);
	}

	inline Error(const Error& err) noexcept{
		memset(&error, 0, sizeof(xmlError));
		// Who likes wrapping C APIs hands up! :(
		xmlCopyError(const_cast<xmlErrorPtr>(&err.error), &error);
	}

	inline Error& operator=(xmlErrorPtr err) noexcept{
		xmlResetError(&error);
		xmlCopyError(err, &error);
		return *this;
	}

	inline Error& operator=(const Error& err) noexcept{
		xmlResetError(&error);
		// Who likes wrapping C APIs hands up! :(
		xmlCopyError(const_cast<xmlErrorPtr>(&err.error), &error);
		return *this;
	}

	inline ~Error() noexcept{
		xmlResetError(&error);
	}

	Error(Error&&) = delete;
	Error& operator=(Error&&) = delete;

	inline xmlError* operator->() noexcept{
		return &error;
	}

	inline const xmlError* operator->() const noexcept{
		return &error;
	}

	inline xmlError* ptr() noexcept{
		return &error;
	}

	inline const xmlError* ptr() const noexcept{
		return &error;
	}

};

class Exception: public std::exception{
private:
    Exception() noexcept;

	static std::string buildErrorMsg(const xmlError* err) noexcept;

	Error ferror;
	std::string str;
public:
	inline Exception(xmlErrorPtr err) noexcept
		:ferror(err),
		  str(buildErrorMsg(err))
	{}

	inline Exception(const Error& err) noexcept
		:ferror(err),
		  str(buildErrorMsg(ferror.ptr()))
	{}

	inline const char* what() const noexcept override{
		return str.c_str();
	}

	inline Error& error() noexcept{
		return ferror;
	}

	inline const Error& error() const noexcept{
		return ferror;
	}

    [[noreturn]] static void throwLastError();
};

//-----------------------------------------------------------------------

class Deleter{
public:
	inline void operator()(xmlParserInputBufferPtr ptr) noexcept{
		xmlFreeParserInputBuffer(ptr);
	}

    inline void operator()(xmlOutputBufferPtr ptr) noexcept{
        xmlOutputBufferClose(ptr);
    }

	inline void operator()(xmlTextReaderPtr ptr) noexcept{
		xmlFreeTextReader(ptr);
	}

    inline void operator()(xmlTextWriterPtr ptr) noexcept{
        xmlFreeTextWriter(ptr);
    }

	inline void operator()(xmlChar* str) noexcept{
        xmlFree(str);
	}
};

class String: public std::unique_ptr<xmlChar, Deleter>{
public:

	using std::unique_ptr<xmlChar, Deleter>::unique_ptr;

	inline const char* c_str() const noexcept{
		return reinterpret_cast<const char*>(get());
	}

        inline bool compare(const String& s) const noexcept{
            return strcmp(reinterpret_cast<const char*>(get()), reinterpret_cast<const char*>(s.get()));
        }

        inline bool compare(const char* s) const noexcept{
            return strcmp(reinterpret_cast<const char*>(get()), s);
        }

        inline bool compare(const std::string& s) const noexcept{
            return strcmp(reinterpret_cast<const char*>(get()), s.c_str());
        }

        template <typename T>
        inline bool operator==(T&& t) const noexcept{ return compare(std::forward<T>(t)) == 0; }
        template <typename T>
        inline bool operator!=(T&& t) const noexcept{ return compare(std::forward<T>(t)) != 0; }
        template <typename T>
        inline bool operator<(T&& t) const noexcept{ return compare(std::forward<T>(t)) < 0; }
        template <typename T>
        inline bool operator>(T&& t) const noexcept{ return compare(std::forward<T>(t)) > 0; }
        template <typename T>
        inline bool operator<=(T&& t) const noexcept{ return compare(std::forward<T>(t)) <= 0; }
        template <typename T>
        inline bool operator>=(T&& t) const noexcept{ return compare(std::forward<T>(t)) >= 0; }

	static inline String wrap(xmlChar* str){
		if (!str)
			throw std::bad_alloc();
		return String(str);
	}

};

inline std::ostream& operator<<(std::ostream& o, const String& s) noexcept(noexcept( o << s.c_str())){
	return o << s.c_str();
}

typedef std::unique_ptr<xmlTextReader, Deleter> TextReader;
typedef std::unique_ptr<xmlTextWriter, Deleter> TextWriter;
typedef std::unique_ptr<xmlParserInputBuffer, Deleter> ParserInputBuffer;
typedef std::unique_ptr<xmlOutputBuffer, Deleter> OutputBuffer;

class InputBufferTextReader{
public:
	class Input{
	public:
		virtual int read(char* buffer, int len) =0;
		virtual void close()=0;
	};

	InputBufferTextReader(Input* input, xmlCharEncoding encoding);

	InputBufferTextReader(const InputBufferTextReader&) = delete;
	InputBufferTextReader(InputBufferTextReader&&) = delete;
	InputBufferTextReader& operator=(const InputBufferTextReader&) = delete;
	InputBufferTextReader& operator=(InputBufferTextReader&&) = delete;

	void expectLocalNameElement(const char* localName);
	void expectRead();
	void expectNext();

	String readString();
	String attribute(const char* name);

	bool read();
	bool next();

	inline int lineNumber() const noexcept{ return xmlTextReaderGetParserLineNumber(ftextReader.get()); }
	inline int columnNumber() const noexcept{ return xmlTextReaderGetParserColumnNumber(ftextReader.get()); }

	inline bool isEmpty() const noexcept { return xmlTextReaderIsEmptyElement(ftextReader.get()); }
	inline int depth() const noexcept{ return xmlTextReaderDepth(ftextReader.get()); }
	std::string localName() const;
	String xlocalName() const;

	inline xmlReaderTypes nodeType() const{
		return xmlReaderTypes(xmlTextReaderNodeType(ftextReader.get()));
	}


private:
	ParserInputBuffer createBuffer(xmlCharEncoding encoding);

	static int xmlInputClose(void* context) noexcept;
	static int xmlInputRead	(void* context, char* buffer, int len);
	static void	xmlStructuredErrorFunc(void * userData, xmlErrorPtr error);

	Input* finput;
	ParserInputBuffer fparserInput;
	TextReader ftextReader;


protected:
	std::exception_ptr exception;
};

class OutputBufferTextWriter{
public:
    class Output{
    public:
        virtual int write(const char* buffer, int len) =0;
        virtual void close()=0;
    };

    void setIndent(int indent);

    void writeStartDocument(const char * version = "1.0",
                            const char * encoding = "utf-8",
                            const char * standalone = "yes");
    void writeEndDocument();
    void writeStartElement(const char* name);
    void writeEndElement();
    void writeAttribute(const char* name, const char* value);
    void writeString(const char* content);
    void writeBase64(const uint8_t* content, int len);

    inline void writeString(const std::string& s){
        writeString(s.c_str());
    }

    template <typename Allocator>
    inline void writeBase64(const std::vector<uint8_t, Allocator>& content){
        writeBase64(content.data(), content.size());
    }

    template <std::size_t size>
    inline void writeBase64(const std::array<uint8_t, size>& content){
        writeBase64(content.data(), content.size());
    }

    OutputBufferTextWriter(Output* output);

    ~OutputBufferTextWriter(){

    }


    OutputBufferTextWriter(const OutputBufferTextWriter&) = delete;
    OutputBufferTextWriter(OutputBufferTextWriter&&) = delete;
    OutputBufferTextWriter& operator=(const OutputBufferTextWriter&) = delete;
    OutputBufferTextWriter& operator=(OutputBufferTextWriter&&) = delete;

    class ElementGuard{
    private:
        OutputBufferTextWriter& writer;

    public:
        inline ElementGuard(OutputBufferTextWriter& writer, const char* name)
            :writer(writer)
        {
            writer.writeStartElement(name);
        }

        inline ~ElementGuard(){
            if (!writer.exception)
                writer.writeEndElement();
        }
    };



private:

    void checkException(int result);

    static int xmlOutputClose(void* context) noexcept;
    static int xmlOutputWrite(void * context, const char * buffer, int len);
    static void	xmlStructuredErrorFunc(void * userData, xmlErrorPtr error);

    Output* foutput;
    TextWriter ftextWriter;

protected:
    std::exception_ptr exception;

    friend class ElementGuard;
};

class IstreamInput: public InputBufferTextReader::Input{
private:
	std::istream& stream;
public:

	inline IstreamInput(std::istream& stream) noexcept
		:stream(stream)
	{}

	virtual int read(char* buffer, int len);
	virtual void close();
};

} // namespace XML

//---------------------------------------------------------------------------------------

namespace Zlib{

class Deflater;

class Inflater{
private:
    z_stream stream;

    voidpf allocFunc(voidpf opaque, uInt items, uInt size){
        unused(opaque);
        try{
            std::size_t* result = reinterpret_cast<std::size_t*>(SafeMemoryManager::allocate(items*size + sizeof(std::size_t)));
            *result = size;
            return result+1;
        }catch(std::bad_alloc&){
            return 0;
        }
    }

    void freeFunc(voidpf opaque, voidpf address){
        unused(opaque);
        std::size_t* ptr = reinterpret_cast<std::size_t*>(address);
        SafeMemoryManager::deallocate(ptr, *ptr);
    }

public:

    inline Inflater(int windowBits = MAX_WBITS){
        memset(&stream, 0, sizeof(z_stream));

        int ret = inflateInit2(&stream, windowBits);
        if (ret != Z_OK)
            throwError("Error initializing decompression", ret, stream.msg);
    }

    Inflater(const Inflater&) = delete;
    Inflater(Inflater&&) = delete;
    Inflater& operator=(const Inflater&) = delete;
    Inflater& operator=(Inflater&&) = delete;

    ~Inflater(){
        inflateEnd(&stream);
    }

    inline operator z_stream*() noexcept{
        return &stream;
    }

    inline z_stream* operator->() noexcept{
        return &stream;
    }

    static void throwError(const char* context, int retval, const char* msg){
        std::ostringstream s;
        s << context << " (" << retval << ")";
        if (msg) s << ": " << msg;
        s << ".";
        throw std::runtime_error(s.str());
    }

    static std::vector<uint8_t> oneShot(const std::vector<uint8_t>& input, int windowBits = MAX_WBITS | 16);
    static SafeVector<uint8_t> oneShot(const SafeVector<uint8_t>& input, int windowBits = MAX_WBITS | 16);

    friend class Deflater;

};

class Deflater{
private:
    z_stream stream;

    voidpf allocFunc(voidpf opaque, uInt items, uInt size){
        unused(opaque);
        try{
            std::size_t* result = reinterpret_cast<std::size_t*>(SafeMemoryManager::allocate(items*size + sizeof(std::size_t)));
            *result = size;
            return result+1;
        }catch(std::bad_alloc&){
            return 0;
        }
    }

    void freeFunc(voidpf opaque, voidpf address){
        unused(opaque);
        std::size_t* ptr = reinterpret_cast<std::size_t*>(address);
        SafeMemoryManager::deallocate(ptr, *ptr);
    }


public:

    inline Deflater(int level = Z_DEFAULT_COMPRESSION,
                    int windowBits = MAX_WBITS,
                    int memLevel=8,
                    int strategy = Z_DEFAULT_STRATEGY){
        memset(&stream, 0, sizeof(z_stream));

        int ret = deflateInit2(&stream, level, Z_DEFLATED, windowBits, memLevel, strategy);
        if (ret != Z_OK)
            Inflater::throwError("Error initializing compression", ret, stream.msg);
    }

    inline Deflater(alloc_func zalloc,
                    free_func  zfree,
                    voidpf     opaque,
                    int level = Z_DEFAULT_COMPRESSION,
                    int windowBits = MAX_WBITS,
                    int memLevel=8,
                    int strategy = Z_DEFAULT_STRATEGY){
        memset(&stream, 0, sizeof(z_stream));

        stream.zalloc = zalloc;
        stream.zfree = zfree;
        stream.opaque = opaque;
        int ret = deflateInit2(&stream, level, Z_DEFLATED, windowBits, memLevel, strategy);
        if (ret != Z_OK)
            Inflater::throwError("Error initializing compression", ret, stream.msg);
    }



    ~Deflater(){
        deflateEnd(&stream);
    }

    inline operator z_stream*() noexcept{
        return &stream;
    }

    inline z_stream* operator->() noexcept{
        return &stream;
    }

    static std::vector<uint8_t> oneShot(const std::vector<uint8_t>& input, int windowBits = MAX_WBITS);
    static SafeVector<uint8_t> oneShot(const SafeVector<uint8_t>& input, int windowBits = MAX_WBITS);
};

}

#endif // WRAPPERS_H
