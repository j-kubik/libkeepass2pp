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

namespace Kdbx {

/** @brief Namepsace for OpenSSL library wrappers.
 *
 * These wrappers are thin and do not isolate library user from underlying
 * OpenSSL library. It is meant only to support C++-style resource management
 * that is not provided by OpenSSL.
*/
namespace OSSL{

/** @brief Class wrapping a set of OpenSSL errors into an exception.*/
class exception: public std::runtime_error{
public:
    /** @brief Structure that represents an OpenSSL error.
     *
     * It stores all data reported by OpenSSL error message.
     */
    struct Error{
        unsigned long code;
        int line;
        int flags;
        std::string file;
        std::string data;
    };

    /** @brief Contains all errors that were reported by OpenSSL function
     *         ERR_get_error_line_data when this exception object was created.
     */
    const std::vector<Error> errors;

    /** @brief Constructs an exception object and fills it with data from
     *         ERR_get_error_line_data OpenSSL function.
     */
    inline exception() noexcept
        :exception(getErrors())
    {}

    /** @brief Clears all OpenSSL errors.
     *
     * This is just a shortcut to ERR_clear_error OpenSSL function.
     */
    static void clearErrors();

private:
    /** @brief Returns a vector of Error objects and fills it with data from
     *         ERR_get_error_line_data OpenSSL function.
     */
    static std::vector<Error> getErrors() noexcept;

    /** @brief Formats a set of Error structures into a single error message.
     *
     * Format of this message is not fixed, but it contains a result of
     * ERR_error_string_n OpenSSL function called with each error code in passed
     * error set.
     */
    static std::string getMessage(const std::vector<Error>& errors) noexcept;

    /** @brief Internal constructor. Used only as a delgate constructor. */
    inline exception(std::vector<Error> errors) noexcept
        :runtime_error(getMessage(errors)),
          errors(std::move(errors))
    {}
};

/** @brief Wrapper class aroud EVP_MD_CTX OpenSSL digest context. */
class Digest{
private:
    EVP_MD_CTX* ctx;
public:

    /** @brief Constructs invalid Digest.
     *
     * The only operation that do not produce unknown behavior on an invalid
     * Digest is assignment, movin or copying into another Digest object or
     * destruction.
     */
    inline Digest() noexcept
        :ctx(nullptr)
    {}

    /** @brief Constructs a valid Digest and initializes it with \p type and
     *         \p impl.
     * @param type Digest type (as specified by OpenSSL);
     * @param impl Digest implementation (as specified by OpenSSL);
     */
    Digest(const EVP_MD* type, ENGINE* impl=nullptr);

    /** @brief Performs deep copy of a digest object. */
    Digest(const Digest& d);

    /** @brief Move constructor for a Digest object.
     *
     * Moved object is left in an invalid (default-constructed) state.
     */
    inline Digest(Digest&& d) noexcept
        :ctx(d.ctx){
        d.ctx = nullptr;
    }

    /** @brief Destroys a Digest object and frees all asociated resources.*/
    ~Digest() noexcept;

    /** @brief Assigns current digest wit a deep copy of \p d.
     *
     * If an excepton is thrown, current exception becomes invalid.
     */
    Digest& operator=(const Digest& d);


    /** @brief Copy/move assignment operator. */
    inline Digest& operator=(Digest d) noexcept{
        swap(*this, d);
        return *this;
    }

    /** @brief Explicit conversion to underlying OpenSSL context handle. */
    inline explicit operator EVP_MD_CTX*() const noexcept{
        return ctx;
    }

    /** @brief Returns \p true if Digest is valid. */
    inline explicit operator bool() const noexcept{
        return ctx;
    }

    /** @brief Returns digest size (as specified by OpenSSL);*/
    inline std::size_t size() const noexcept{
        return EVP_MD_CTX_size(ctx);
    }

    /** @brief Returns digest block size (as specified by OpenSSL);*/
    inline std::size_t block_size() const noexcept{
        return EVP_MD_CTX_block_size(ctx);
    }

    /** @brief Returns digest type (as specified by OpenSSL);*/
    inline int type() const noexcept{
        return EVP_MD_CTX_type(ctx);
    }

    /** @brief Returns an OpenSSL handle to message digest type;*/
    inline const EVP_MD* md() const noexcept{
        return EVP_MD_CTX_md(ctx);
    }

    /** @brief Reinitializes Digest object.
     * @param type Digest type (as specified by OpenSSL);
     * @param impl Digest implementation (as specified by OpenSSL);
     *
     * This method can be used in order to re-use a Digest object.
     */
    void init(const EVP_MD *type, ENGINE *impl = nullptr);

    /** @brief Updates a digest with more data. */
    void update(const uint8_t* data, std::size_t size);

    /** @brief Updates a digest with more data. */
    void update(const char* data, std::size_t size){
        update(reinterpret_cast<const uint8_t*>(data), size);
    }

    /** @brief Updates a digest with more data. */
    void update(const std::vector<uint8_t>& data, std::size_t size){
        update(data.data(), size);
    }

    /** @brief Updates a digest with more data. */
    void update(const std::vector<uint8_t>& data){
        update(data.data(), data.size());
    }

    /** @brief Updates a digest with more data. */
    void update(const SafeVector<uint8_t>& data, std::size_t size){
        update(data.data(), size);
    }

    /** @brief Updates a digest with more data. */
    void update(const SafeVector<uint8_t>& data){
        update(data.data(), data.size());
    }

    /** @brief Updates a digest with more data. */
    template <std::size_t s>
    void update(const std::array<uint8_t, s>& data){
        update(data.data(), s);
    }

    /** @brief Returns final value of a digest.
     * @param data Pointer to a buffer where the digest is to be stored.
     *             This buffer must be at least size() bytes long.
     * @return Number of bytes stroed in \p data buffer. At most size().
     *
     * After a call to final(), no further calls to update() can be made until
     * Digest is reinitialized.
     */
    unsigned int final(uint8_t* data);

    /** @brief Stores final value of a digest in  \p data buffer.
     * @param data Buffer in which data is to be stored.
     *
     * After a call to final(), no further calls to update() can be made until
     * Digest is reinitialized.
     */
    void final(SafeVector<uint8_t>& data);

    /** @brief Returns final value of a digest.
     * @return Buffer containing the digest.
     *
     * After a call to final(), no further calls to update() can be made until
     * Digest is reinitialized.
     */
    std::vector<uint8_t> final();

    /** @brief Returns final value of a digest.
     * @return Safe buffer containing the digest.
     *
     * After a call to final(), no further calls to update() can be made until
     * Digest is reinitialized.
     */
    SafeVector<uint8_t> safeFinal();

    /** @brief Returns final value of a digest.
     * @param data Buffer in which data is to be stored.
     *
     * After a call to final(), no further calls to update() can be made until
     * Digest is reinitialized.
     */
    template <std::size_t s>
    void final(std::array<uint8_t, s>& result){
        assert(size() == s);
        unsigned int written;
        if (EVP_DigestFinal_ex(ctx, result.data(), &written)!=1)
            throw exception();
        assert(written == s);
    }

    /** @brief Swaps two digest objects. */
    friend inline void swap(Digest& d1, Digest& d2) noexcept{
        using std::swap;
        swap(d1.ctx, d2.ctx);
    }

    /** @brief Coputes a disgest of a datab buffer in one call.
     * @param type Digest type (as specified by OpenSSL);
     * @param t Buffer to store digest output;
     * @param args Arguments specyfying digest input (as in update() method);
     *
     * The result is well defined if both \p t and  \p args specify the same, or
     * overlapping buffers.
     */
    template <typename T, typename ...Args>
    static std::enable_if_t<!std::is_same<std::decay_t<T>, ENGINE*>::value &&
                            !std::is_null_pointer<std::decay<T>>::value>
    oneShot(const EVP_MD* type, T&& t, Args&& ...args){
        Digest d(type);
        d.update(std::forward<Args>(args)...);
        d.final(std::forward<T>(t));
    }

    /** @brief Coputes a disgest of a datab buffer in one call.
     * @param type Digest type (as specified by OpenSSL);
     * @param t Buffer to store digest output;
     * @param args Arguments specyfying digest input (as in update() method);
     * @param impl Digest implementation (as specified by OpenSSL);
     *
     * The result is well defined if both \p t and  \p args specify the same, or
     * overlapping buffers.
     */
    template <typename T, typename ...Args>
    static std::enable_if_t<!std::is_same<std::decay_t<T>, ENGINE*>::value &&
                            !std::is_null_pointer<std::decay<T>>::value>
    oneShot(const EVP_MD* type, ENGINE* engine, T&& t, Args&& ...args){
        Digest d(type, engine);
        d.update(std::forward<Args>(args)...);
        d.final(std::forward<T>(t));
    }

};

/** @brief Wrapper class aroud EVP_CIPHER_CTX OpenSSL cipher context. */
class EvpCipher{
private:
    EVP_CIPHER_CTX* ctx;

public:

    /** @brief Constructs invalid EvpCipher.
     *
     * The only operation that do not produce unknown behavior on an invalid
     * EvpCipher is assignment, moving into another EvpCipher object or
     * destruction.
     */
    inline EvpCipher() noexcept
        :ctx(nullptr)
    {}

    //ToDo: Should I use an enum for enc? I kkep going to doc every time I use
    //      those functions; this might be of benefit.
    /** @brief Constructs a valid Digest and initializes it with \p type,
     *         \p impl \p key, \p iv and \p enc.
     * @param type Cipher type (as specified by OpenSSL);
     * @param impl Cipher implementation (as specified by OpenSSL);
     * @param key Encryption key;
     * @param iv Encryption IV;
     * @param enc 1 for encryption, 0 for decryption and -1 to leave the value
     *        unchanged.
     */
    EvpCipher(const EVP_CIPHER *type,
                 ENGINE *impl = nullptr,
                 const unsigned char *key = nullptr,
                 const unsigned char *iv = nullptr,
                 int enc = -1);


    /** @brief Move constructor for a EvpCipher object.
     *
     * Moved object is left in an invalid (default-constructed) state.
     */
    inline EvpCipher(EvpCipher&& c) noexcept
        :ctx(c.ctx){
        c.ctx = nullptr;
    }

    EvpCipher(const EvpCipher&) = delete;

    /** @brief Destroys an EvpCipher object and frees all asociated resources.*/
    ~EvpCipher() noexcept;

    EvpCipher& operator=(const EvpCipher&) = delete;
    EvpCipher& operator=(EvpCipher&&) = delete;

    /** @brief Copy/move assignment operator. */
    inline EvpCipher& operator=(EvpCipher ctx){
        swap(*this, ctx);
        return *this;
    }

    /** @brief Explicit conversion to underlying OpenSSL cipher handle. */
    inline operator EVP_CIPHER_CTX*() noexcept{
        return ctx;
    }

    /** @brief Returns \p true if EvpCipher is valid. */
    inline explicit operator bool() const noexcept{
        return ctx;
    }

    /** @brief Returns cipher block size (as specified by OpenSSL);*/
    inline std::size_t block_size() const noexcept{
        return  EVP_CIPHER_CTX_block_size(ctx);
    }

    void set_padding(bool padding) noexcept;

    /** @brief Updates EvpCipher configuration.
     * @param type Cipher type (as specified by OpenSSL);
     * @param impl Cipher implementation (as specified by OpenSSL);
     * @param key Encryption key;
     * @param iv Encryption IV;
     * @param enc 1 for encryption, 0 for decryption and -1 to leave the value
     *        unchanged.
     *
     * This method can be used in order to re-use a EvpCipher object, or update
     * it's configuration. Configuration update is only possible if no data was
     * passed through the EvpCipher object.
     */
    void init(const EVP_CIPHER *type,
              ENGINE *impl = nullptr,
              const unsigned char *key = nullptr,
              const unsigned char *iv = nullptr,
              int enc = -1);

    /** @brief Resets EvpCipher to a valid, default-initialized state.
     *
     * This method is useful for re-using an EvpCipher object.
     */
    void reset();

    /** @brief Updates EvpCipher object with a portion of data.
     * @param out Pointer to output buffer;
     * @param in Pointer to input data buffer;
     * @param inl Size of data in input buffer;
     * @return Number of bytes written to output buffer;
     *
     * Output buffer must be at least (inl+block_size()) bytes long for decrypt
     * cipher context, and at least (inl+block_size()-1) bytes long for encrypt
     * cipher context.
     */
    int update(unsigned char *out, unsigned char *in, int inl);

    /** @brief Finishes EvpCipher processing.
     * @param out Pointer to output buffer;
     * @return Number of bytes written to output buffer;
     *
     * Output buffer must be at least block_size() bytes long.
     */
    int final(unsigned char *out);


    /** @brief Swaps two EvpCipher objects. */
    friend inline void swap(EvpCipher& c1, EvpCipher& c2) noexcept{
        using std::swap;
        swap(c1.ctx, c2.ctx);
    }
};

/** @brief Generates \p size random bytes and stores it in \p data buffer.*/
inline void rand(uint8_t* data, std::size_t size){
    if (RAND_bytes(data, size) != 1)
        throw exception();
}

/** @brief Generates \p size random bytes and stores it in \p container.*/
template <typename T, typename = typename std::enable_if<
              std::is_same<
                  typename std::remove_volatile<
                      decltype(std::declval<T>().data())>::type,
                  uint8_t*>::value
              >::type>
inline void rand(T& container, std::size_t size){
    rand(container.data(), size);
}

/** @brief Generates \p container.size() random bytes and stores it in
 *         \p container.*/
template <typename T, typename = typename std::enable_if<
              std::is_same<
                  typename std::remove_volatile<
                      decltype(std::declval<T>().data())>::type,
                  uint8_t*>::value
              >::type>
inline void rand(T& container){
    rand(container.data(), container.size());
}

/** @brief Generates \p container.size() random bytes and returns it in
 *         newly created \p container of type Container.*/
template <typename Container, typename ...Args, typename = typename std::enable_if<
              std::is_same<
                  typename std::remove_volatile<
                      decltype(std::declval<Container>().data())
                      >::type,
                  uint8_t*>::value &&
              std::is_same<
                  typename std::remove_volatile<
                      decltype(std::declval<Container>().size())
                      >::type,
                  std::size_t>::value
              >::type>
inline Container rand(Args&& ...args){
    Container result(args...);
    rand(result);
    return result;
}

}

//------------------------------------------------------------------------------

/** @brief Namespace XML contains wrappers for some libXml structures that make
 *         an attempt at providing easier resource management in C++ programs.
 *
 * Those wrappers are thin, and do not isolate user form underlying library.
 * Knowledg of libXml is necesary as the set of functionality these wrappers
 * provide is not exhaustive and only documented up to the diferences to libXml.
 */
namespace XML{

#ifdef KEEPASS2PP_VERBOSE_XML_ERRORS
/** @brief Translates numeric error code to string equal to the enum flag name.
 *
 * This function is only available if library was configured with
 * --enable-verbose-xml-errors flag. If verbose XML errors were configured,
 * KEEPASS2PP_VERBOSE_XML_ERRORS symbol is #define's.
*/
const char* toString(xmlErrorLevel domain) noexcept;

/** @brief Translates numeric error code to string equal to the enum flag name.
 *
 * This function is only available if library was configured with
 * --enable-verbose-xml-errors flag. If verbose XML errors were configured,
 * KEEPASS2PP_VERBOSE_XML_ERRORS symbol is #define's.
*/
const char* toString(xmlErrorDomain domain) noexcept;

/** @brief Translates numeric error code to string equal to the enum flag name.
 *
 * This function is only available if library was configured with
 * --enable-verbose-xml-errors flag. If verbose XML errors were configured,
 * KEEPASS2PP_VERBOSE_XML_ERRORS symbol is #define's.
*/
const char* toString(xmlParserErrors parserError) noexcept;

/** @brief Translates numeric error code to string equal to the enum flag name.
 *
 * This function is only available if library was configured with
 * --enable-verbose-xml-errors flag. If verbose XML errors were configured,
 * KEEPASS2PP_VERBOSE_XML_ERRORS symbol is #define's.
*/
const char* toString(xmlReaderTypes readerType) noexcept;

#else
/** @brief Translates numeric error code to string equal to the enum flag name.
 *
 * This function is only available if library was configured with
 * --enable-verbose-xml-errors flag. If verbose XML errors were configured,
 * KEEPASS2PP_VERBOSE_XML_ERRORS symbol is #define's.
*/
template <typename T>
const char* toString(T t) noexcept{
    static_assert(false, "This function is not available if keepass2pp is compiled "
                         "without verbose xml support. Use KEEPASS2PP_VERBOSE_XML_ERRORS "
                         "to determine support status." );
    return false;
}
#endif

/** @brief Wraps xmlError struture into C++ class. */
class Error{
private:
    xmlError error;

public:

    /** @brief Constructs empty Error object. */
    inline Error() noexcept{
        memset(&error, 0, sizeof(xmlError));
    }

    /** @brief Constructs Error object that contains a copy of \p err. */
    inline Error(xmlErrorPtr err) noexcept{
        memset(&error, 0, sizeof(xmlError));
        xmlCopyError(err, &error);
    }

    /** @brief Constructs Error object that contains a copy of \p err. */
    inline Error(const Error& err) noexcept{
        memset(&error, 0, sizeof(xmlError));
        // Who likes wrapping C APIs hands up! :(
        xmlCopyError(const_cast<xmlErrorPtr>(&err.error), &error);
    }

    /** @brief Assigns a copy of \p err error to current Error object. */
    inline Error& operator=(xmlErrorPtr err) noexcept{
        xmlResetError(&error);
        xmlCopyError(err, &error);
        return *this;
    }

    /** @brief Assigns a copy of \p err error to current Error object. */
    inline Error& operator=(const Error& err) noexcept{
        xmlResetError(&error);
        // Who likes wrapping C APIs hands up! :(
        xmlCopyError(const_cast<xmlErrorPtr>(&err.error), &error);
        return *this;
    }

    /** @brief Destroys an Error object. */
    inline ~Error() noexcept{
        xmlResetError(&error);
    }

    Error(Error&&) = delete;
    Error& operator=(Error&&) = delete;

    /** @brief xmlError field access helper. */
    inline xmlError* operator->() noexcept{
        return &error;
    }

    /** @brief xmlError field access helper. */
    inline const xmlError* operator->() const noexcept{
        return &error;
    }

    /** @brief Returns xmlError structure access pointer. */
    inline xmlError* ptr() noexcept{
        return &error;
    }

    /** @brief Returns xmlError structure access pointer. */
    inline const xmlError* ptr() const noexcept{
        return &error;
    }

};


/** @brief Wraps an Error object into an std::exception class. */
class Exception: public std::runtime_error{
private:
    /** @brief Constructs default Exception.
     *
     * Default exception has no data, and reports an unknown XML error from
     * what().
     */
    Exception() noexcept;

    /** @brief Creates error message from xmlError structure.
     *
     * If the library was compiled with --enable-verbose-xml-errors flag,
     * returned error message will contain flag-descriptions instad of numeric
     * values.
     */
    static std::string buildErrorMsg(const xmlError* err) noexcept;

    Error ferror;
public:
    /** @breif Constructs an Exception containig a copy of \p err error.*/
    inline Exception(xmlErrorPtr err) noexcept
        :runtime_error(buildErrorMsg(err)),
          ferror(err)
    {}

    /** @breif Constructs an Exception containig a copy of \p err error.*/
    inline Exception(const Error& err) noexcept
        :runtime_error(buildErrorMsg(err.ptr())),
         ferror(err)
    {}

    /** @brief Returns contained Error object.*/
    inline Error& error() noexcept{
        return ferror;
    }

    /** @brief Returns contained Error object.*/
    inline const Error& error() const noexcept{
        return ferror;
    }

    /** @brief Throws an Exception object containig a copy of error returned by
     *         xmlGetLastError().
     *
     * If xmlGetLastError returns nullptr, thrown excpetion reports an unknown
     * XML error from what(), and contains empty (default-constructed) Error
     * object.
     *
     * If error returned from xmlGetLastError has error code XML_ERR_NO_MEMORY,
     * an instance of std::bad_alloc is thrown instead. This is done in order to
     * unify allocation related exceptions.
     *
     * This method doesn't return.
     */
    [[noreturn]] static void throwLastError();
};

//-----------------------------------------------------------------------

/** @brief Helper class used as deleter type for std::uniqie_ptr class
 *        template.*/
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

/** @brief Owning wrapper for an xmlString type.*/
class String: public std::unique_ptr<xmlChar, Deleter>{
public:

    using std::unique_ptr<xmlChar, Deleter>::unique_ptr;

    /** @brief Returns underlying string or nullptr if none.*/
    inline const char* c_str() const noexcept{
        return reinterpret_cast<const char*>(get());
    }

    /** @brief Lexicograph-compare String to s.
     * @return -1 if *this < s; 0 if *this == s; 1 if *this > s;
     */
    inline int compare(const String& s) const noexcept{
        return strcmp(reinterpret_cast<const char*>(get()), reinterpret_cast<const char*>(s.get()));
    }

    /** @brief Lexicograph-compare String to s.
     * @return -1 if *this < s; 0 if *this == s; 1 if *this > s;
     */
    inline int compare(const char* s) const noexcept{
        return strcmp(reinterpret_cast<const char*>(get()), s);
    }

    /** @brief Lexicograph-compare String to t.
     * @return -1 if *this < s; 0 if *this == s; 1 if *this > s;
     */
    inline int compare(const std::string& s) const noexcept{
        return strcmp(reinterpret_cast<const char*>(get()), s.c_str());
    }

    /** @brief Lexicograph-compare String to t.*/
    template <typename T>
    inline bool operator==(T&& t) const noexcept{ return compare(std::forward<T>(t)) == 0; }
    /** @brief Lexicograph-compare String to t.*/
    template <typename T>
    inline bool operator!=(T&& t) const noexcept{ return compare(std::forward<T>(t)) != 0; }
    /** @brief Lexicograph-compare String to t.*/
    template <typename T>
    inline bool operator<(T&& t) const noexcept{ return compare(std::forward<T>(t)) < 0; }
    /** @brief Lexicograph-compare String to t.*/
    template <typename T>
    inline bool operator>(T&& t) const noexcept{ return compare(std::forward<T>(t)) > 0; }
    /** @brief Lexicograph-compare String to t.*/
    template <typename T>
    inline bool operator<=(T&& t) const noexcept{ return compare(std::forward<T>(t)) <= 0; }
    /** @brief Lexicograph-compare String to t.*/
    template <typename T>
    inline bool operator>=(T&& t) const noexcept{ return compare(std::forward<T>(t)) >= 0; }

    /** @brief Wraps \str string into String object. Takes ownership of \p str
     *         buffer.*/
    static inline String wrap(xmlChar* str){
        if (!str)
            throw std::bad_alloc();
        return String(str);
    }

};

/** @biref std::ostream output operator for String class.
 *
 * String class must be a valid string; ie. must not convert to \p false.*/
inline std::ostream& operator<<(std::ostream& o, const String& s) noexcept(noexcept( o << s.c_str())){
    return o << s.c_str();
}

/** @brief Unique pointer to xmlTextReader resource.*/
typedef std::unique_ptr<xmlTextReader, Deleter> TextReader;
/** @brief Unique pointer to xmlTextWriter resource.*/
typedef std::unique_ptr<xmlTextWriter, Deleter> TextWriter;
/** @brief Unique pointer to xmlParserInputBuffer resource.*/
typedef std::unique_ptr<xmlParserInputBuffer, Deleter> ParserInputBuffer;
/** @brief Unique pointer to xmlOutputBuffer resource.*/
typedef std::unique_ptr<xmlOutputBuffer, Deleter> OutputBuffer;

/** @brief xmlTextReader wrapper class. */
class InputBufferTextReader{
public:

    /** Interface class that is used as an bastract interface to
     * xmlParserInputBuffer.*/
    class Input{
    public:
       /** @brief Reads exactly \p len bytes into \p buffer.*/
        virtual int read(char* buffer, int len) =0;

       /** @brief Closes input buffer.
        *
        * It indicates no further read() will be called on that Input.
        */
        virtual void close()=0;
    };

    /** @brief Creates new xmlTextReader.
     * @param input Input object to get the data from;
     * @param encoding Encoding of input data (as sepcified by libXml)
     *
     * InputBufferTextReader does not take ownership of input object it uses.
     * Caller should ensure that input object remains valid for as long as
     * InputBufferTextReader exists.
     */
    InputBufferTextReader(Input* input, xmlCharEncoding encoding);

    InputBufferTextReader(const InputBufferTextReader&) = delete;
    InputBufferTextReader(InputBufferTextReader&&) = delete;
    InputBufferTextReader& operator=(const InputBufferTextReader&) = delete;
    InputBufferTextReader& operator=(InputBufferTextReader&&) = delete;


    //void expectLocalNameElement(const char* localName);
    void expectRead();
    void expectNext();

    String readString();
    String attribute(const char* name);

    /** @brief read next XML node in.
     * @return true if node was read, false if there is no more nodes.
     *
     * This is a wrapper to xmlTextReaderRead function. If an error is
     * encountered, it throws an exception.
     */
    bool read();

    /** @brief read next XML node in. Skips subtree of current node if any.
     * @return true if node was read, false if there is no more nodes.
     *
     * This is a wrapper to xmlTextReaderNext function. If an error is
     * encountered, it throws an exception.
     */
    bool next();

    /** @brief Current line number. */
    inline int lineNumber() const noexcept{ return xmlTextReaderGetParserLineNumber(ftextReader.get()); }
    /** @brief Current column number. */
    inline int columnNumber() const noexcept{ return xmlTextReaderGetParserColumnNumber(ftextReader.get()); }

    /** @brief Checks if current node is an empty element. */
    inline bool isEmpty() const noexcept { return xmlTextReaderIsEmptyElement(ftextReader.get()); }
    /** @brief Checks current depth. */
    inline int depth() const noexcept{ return xmlTextReaderDepth(ftextReader.get()); }

    /** @brief Returns local name of current XML node.*/
    std::string localName() const;

    /** @brief Returns local name of current XML node.*/
    String xlocalName() const;

    /** @brief Returns current node type (as sepcified by libXml). */
    inline xmlReaderTypes nodeType() const{
        return xmlReaderTypes(xmlTextReaderNodeType(ftextReader.get()));
    }


private:
    /** @brief Create a new parser input buffer. */
    ParserInputBuffer createBuffer(xmlCharEncoding encoding);

    /** @brief libXml callback. */
    static int xmlInputClose(void* context) noexcept;
    /** @brief libXml callback. */
    static int xmlInputRead	(void* context, char* buffer, int len);
    /** @brief libXml callback. */
    static void	xmlStructuredErrorFunc(void * userData, xmlErrorPtr error);

    Input* finput;
    ParserInputBuffer fparserInput;
    TextReader ftextReader;


protected:
    std::exception_ptr exception;
};

/** @brief xmlTextReader wrapper class. */
class OutputBufferTextWriter{
public:

    /** Interface class that is used as an bastract interface to
     * xmlOutputBuffer.*/
    class Output{
    public:
        /** @brief Called when data is to be writen to an output buffer. */
        virtual int write(const char* buffer, int len) =0;
        /** @brief Called when writing to a bufer is concluded. */
        virtual void close()=0;
    };

    /** @brief Constructs a Text writer that uses passed output.
     *
     * OutputBufferTextWriter does not take ownership of output object it uses.
     * Caller should ensure that output object remains valid for as long as
     * OutputBufferTextWriter exists.
     */
    OutputBufferTextWriter(Output* output);

    OutputBufferTextWriter(const OutputBufferTextWriter&) = delete;
    OutputBufferTextWriter(OutputBufferTextWriter&&) = delete;
    OutputBufferTextWriter& operator=(const OutputBufferTextWriter&) = delete;
    OutputBufferTextWriter& operator=(OutputBufferTextWriter&&) = delete;

    /** @brief Changes XML formatting indent.
     *
     * This is a wrapper to xmlTextWriterSetIndent function. If an error is
     * encountered, it throws an exception.
     */
    void setIndent(int indent);

    /** @brief Writes a start document entity.
     *
     * This is a wrapper to xmlTextWriterStartDocument function. If an error is
     * encountered, it throws an exception.
     */
    void writeStartDocument(const char * version = "1.0",
                            const char * encoding = "utf-8",
                            const char * standalone = "yes");

    /** @brief Writes a end document entity.
     *
     * This is a wrapper to xmlTextWriterEndDocument function. If an error is
     * encountered, it throws an exception.
     */
    void writeEndDocument();

    /** @brief Writes an element start entity.
     *
     * This is a wrapper to xmlTextWriterStartElement function. If an error is
     * encountered, it throws an exception.
     */
    void writeStartElement(const char* name);

    /** @brief Writes an element end entity.
     *
     * This is a wrapper to xmlTextWriterEndElement function. If an error is
     * encountered, it throws an exception.
     */
    void writeEndElement();

    /** @brief Writes an element attribute.
     *
     * This is a wrapper to xmlTextWriterWriteAttribute function. If an error is
     * encountered, it throws an exception.
     */
    void writeAttribute(const char* name, const char* value);

    /** @brief Writes a text entity.
     *
     * This is a wrapper to xmlTextWriterWriteString function. If an error is
     * encountered, it throws an exception.
     */
    void writeString(const char* content);

    /** @brief Writes a bianry buffer as base64 encoded text entity.
     *
     * This is a wrapper to xmlTextWriterWriteString function. If an error is
     * encountered, it throws an exception.
     */
    void writeBase64(const uint8_t* content, int len);

    /** @brief Writes a text entity.
     *
     * This is a wrapper to xmlTextWriterWriteString function. If an error is
     * encountered, it throws an exception.
     */
    inline void writeString(const std::string& s){
        writeString(s.c_str());
    }

    /** @brief Writes a bianry buffer as base64 encoded text entity.
     *
     * This is a wrapper to xmlTextWriterWriteString function. If an error is
     * encountered, it throws an exception.
     */
    template <typename Allocator>
    inline void writeBase64(const std::vector<uint8_t, Allocator>& content){
        writeBase64(content.data(), content.size());
    }

    /** @brief Writes a bianry buffer as base64 encoded text entity.
     *
     * This is a wrapper to xmlTextWriterWriteString function. If an error is
     * encountered, it throws an exception.
     */
    template <std::size_t size>
    inline void writeBase64(const std::array<uint8_t, size>& content){
        writeBase64(content.data(), content.size());
    }

private:

    /** @brief Checks return status and throws an exception if it indicates
     *         an error.*/
    void checkException(int result);


    /** @brief libXml callback. */
    static int xmlOutputClose(void* context) noexcept;
    /** @brief libXml callback. */
    static int xmlOutputWrite(void * context, const char * buffer, int len);
    /** @brief libXml callback. */
    static void	xmlStructuredErrorFunc(void * userData, xmlErrorPtr error);

    Output* foutput;
    TextWriter ftextWriter;

protected:
    std::exception_ptr exception;
};

/** @brief Basic xml input buffer, that uses an istream object as data source.*/
class IstreamInput: public InputBufferTextReader::Input{
private:
    std::istream& stream;
public:

    /** @brief Constructs IstreamInput.
     * @param stream Input stream to use as data source.
     *
     * IstreamInput doesn't take ownership of stream object. It is up to the
     * caller to ensure that stream reamins valid as long as IstreamInput
     * exists.
     */
    inline IstreamInput(std::istream& stream) noexcept
        :stream(stream)
    {}

    /** @brief Overload of InputBufferTextReader::Input method. */
    virtual int read(char* buffer, int len);
    /** @brief Overload of InputBufferTextReader::Input method. */
    virtual void close();
};

/** @brief Basic xml output buffer, that uses an ostream object as data sink.*/
class OstreamOutput: public OutputBufferTextWriter::Output{
private:
    std::ostream& stream;
public:

    /** @brief Constructs IstreamInput.
     * @param stream Input stream to use as data source.
     *
     * IstreamInput doesn't take ownership of stream object. It is up to the
     * caller to ensure that stream reamins valid as long as IstreamInput
     * exists.
     */
    inline OstreamOutput(std::ostream& stream) noexcept
        :stream(stream)
    {}

    /** @brief Overload of OutputBufferTextWriter::Output method. */
    virtual int write(const char* buffer, int len);
    /** @brief Overload of OutputBufferTextWriter::Output method. */
    virtual void close();
};

} // namespace XML

//---------------------------------------------------------------------------------------

/** @brief Namespace Zlib contains wrappers for some libZ structures that make
 *         an attempt at providing easier resource management in C++ programs.
 *
 * Those wrappers are thin, and do not isolate user form underlying library.
 * Knowledge of libZ is necesary as the set of functionality these wrappers
 * provide is not exhaustive and only documented up to the diferences to libZ.
 */
namespace Zlib{

enum class AllocType{
    Default, Safe
};

class Deflater;

/** @brief Inflater class is a libZ stream decompression class.
 *
 * It is a wrapper around libZ z_stream structure.
 */
class Inflater{
private:
    z_stream stream;

    /** @brief libZ-style safe memeory allocation function.*/
    static voidpf allocFunc(voidpf opaque, uInt items, uInt size) noexcept;

    /** @brief libZ-style safe memeory allocation function.*/
    static void freeFunc(voidpf opaque, voidpf address) noexcept;

public:

    /** @brief Construct an Inflater.
     * @param windowBits base two logarithm of the maximum window size;
     *        It must be bigger or equal to the windowBits paramater used for
     *        compression of data that is to be decompressed.
     * @param type Inflater uses safe memory allocation functions if set to
     *        AllocType::Default.
     */
    Inflater(int windowBits = MAX_WBITS,
             AllocType type = AllocType::Default);

    Inflater(const Inflater&) = delete;
    Inflater(Inflater&&) = delete;
    Inflater& operator=(const Inflater&) = delete;
    Inflater& operator=(Inflater&&) = delete;

    /** @brief Destroys an Inflater. */
    inline ~Inflater() noexcept{
        inflateEnd(&stream);
    }

    /** @brief Accessor for underlying z_stream structure. */
    inline operator z_stream*() noexcept{
        return &stream;
    }

    /** @brief Accessor for underlying z_stream structure. */
    inline z_stream* operator->() noexcept{
        return &stream;
    }

    /** @brief One shot decompression function.
     * @param input Data to be decompressed;
     * @param windowBits base two logarithm of the maximum window size.
     *        It must be bigger or equal to the windowBits paramater used for
     *        compression of data that is to be decompressed.
     * @param type Inflater uses safe memory allocation functions if set to
     *        AllocType::Default.
     *
     * Decompresses entire buffer and returns it in one operation.
     */
    static std::vector<uint8_t> oneShot(const std::vector<uint8_t>& input,
                                        int windowBits = MAX_WBITS,
                                        AllocType type = AllocType::Default);

    /** @brief One shot decompression function.
     * @param input Data to be decompressed;
     * @param windowBits base two logarithm of the maximum window size.
     *        It must be bigger or equal to the windowBits paramater used for
     *        compression of data that is to be decompressed.
     * @param type Inflater uses safe memory allocation functions if set to
     *        AllocType::Default.
     *
     * Decompresses entire buffer and returns it in one operation.
     */
    static SafeVector<uint8_t> oneShot(const SafeVector<uint8_t>& input,
                                       int windowBits = MAX_WBITS,
                                       AllocType type = AllocType::Default);

    /** @brief Utility function that composes an excpetion message and throws
     *         std::runtime_error.
     * @param context String describing context in which error code was
     *        received;
     * @param retVal libZ error code;
     * @param msg libZ error message.
     */
    static void throwError(const char* context, int retval, const char* msg);

    friend class Deflater;
};

/** @brief Inflater class is a libZ stream compression class.
 *
 * It is a wrapper around libZ z_stream structure.
 */
class Deflater{
private:
    z_stream stream;

public:

    /** @brief Construct a Deflater.
     * @param level Compression level (as specified by libZ)
     * @param windowBits base two logarithm of the maximum window size (as
     *        specified by libZ). Data compressed by this Deflater must be
     *        decompressed with windowBits greater or equal to the value set
     *        here.
     * @param memLevel Algorithm memory usage (as specified by libZ). Must be
     *        between 1 (least memory) and 9 (most memory);
     * @param strategy used to tune the compression algorithm (as specified by
     *        libZ);
     * @param type Inflater uses safe memory allocation functions if set to
     *        AllocType::Default.
     */
    Deflater(int level = Z_DEFAULT_COMPRESSION,
             int windowBits = MAX_WBITS,
             int memLevel=8,
             int strategy = Z_DEFAULT_STRATEGY,
             AllocType type = AllocType::Default);

    /** @brief Destroys a Deflater. */
    inline ~Deflater() noexcept{
        deflateEnd(&stream);
    }

    /** @brief Accessor for underlying z_stream structure. */
    inline operator z_stream*() noexcept{
        return &stream;
    }

    /** @brief Accessor for underlying z_stream structure. */
    inline z_stream* operator->() noexcept{
        return &stream;
    }

    /** @brief One shot decompression function.
     * @param input Data to be compressed;
     * @param level Compression level (as specified by libZ)
     * @param windowBits base two logarithm of the maximum window size (as
     *        specified by libZ). Data compressed by this Deflater must be
     *        decompressed with windowBits greater or equal to the value set
     *        here.
     * @param memLevel Algorithm memory usage (as specified by libZ). Must be
     *        between 1 (least memory) and 9 (most memory);
     * @param strategy used to tune the compression algorithm (as specified by
     *        libZ);
     * @param type Inflater uses safe memory allocation functions if set to
     *        AllocType::Default.
     *
     * Compresses entire buffer and returns it in one operation.
     */
    static std::vector<uint8_t> oneShot(const std::vector<uint8_t>& input,
                                        int level = Z_DEFAULT_COMPRESSION,
                                        int windowBits = MAX_WBITS,
                                        int memLevel=8,
                                        int strategy = Z_DEFAULT_STRATEGY,
                                        AllocType type = AllocType::Default);

    /** @brief One shot decompression function.
     * @param input Data to be compressed;
     * @param level Compression level (as specified by libZ)
     * @param windowBits base two logarithm of the maximum window size (as
     *        specified by libZ). Data compressed by this Deflater must be
     *        decompressed with windowBits greater or equal to the value set
     *        here.
     * @param memLevel Algorithm memory usage (as specified by libZ). Must be
     *        between 1 (least memory) and 9 (most memory);
     * @param strategy used to tune the compression algorithm (as specified by
     *        libZ);
     * @param type Inflater uses safe memory allocation functions if set to
     *        AllocType::Default.
     *
     * Compresses entire buffer and returns it in one operation.
     */
    static SafeVector<uint8_t> oneShot(const SafeVector<uint8_t>& input,
                                       int level = Z_DEFAULT_COMPRESSION,
                                       int windowBits = MAX_WBITS,
                                       int memLevel=8,
                                       int strategy = Z_DEFAULT_STRATEGY,
                                       AllocType type = AllocType::Default);
};

}

}

#endif // WRAPPERS_H
