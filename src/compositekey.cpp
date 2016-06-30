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
#include <cassert>

#include <openssl/sha.h>

#include "../include/libkeepass2pp/compositekey.h"
#include "../include/libkeepass2pp/util.h"
#include "../include/libkeepass2pp/wrappers.h"

namespace Kdbx {

CompositeKey::Key::~Key() noexcept
{}

namespace {

class PasswordKey: public CompositeKey::Key{
private:
    SafeString<char> pass;
public:

    inline PasswordKey(SafeString<char> pass) noexcept
        :Key(Type::Password),
          pass(std::move(pass))
    {}

    SafeVector<uint8_t> data() const override{
        OSSL::Digest d(EVP_sha256());
        d.update(pass.data(), pass.size());
        return d.safeFinal();
    }
};

//ToDo: Implement older key-file format...
//ToDo: ifstream read buffer should also be made safe.
class FileKey: public CompositeKey::Key{
private:
    SafeString<char> filename;
public:

    inline FileKey(SafeString<char> filename) noexcept
        :Key(Type::Password),
          filename(std::move(filename))
    {}

    SafeVector<uint8_t> data() const override{

        std::ifstream keyFile(filename.c_str());
        if (!keyFile.is_open() || !keyFile.good()){
            std::stringstream s;
            s << "Error opening file: '" << filename << "'.";
            throw std::runtime_error(s.str());
        }

        try{
            XML::IstreamInput xmlInput(keyFile);

            XML::InputBufferTextReader reader(&xmlInput, XML_CHAR_ENCODING_UTF8);
            reader.expectRead();
            xmlReaderTypes type = reader.nodeType();

            if (type != XML_READER_TYPE_ELEMENT ||
                    strcmp(reader.xlocalName().c_str(), "KeyFile") != 0){
                throw std::runtime_error("Invalid key file: no 'KeyFile' root element.");
            }

            if (reader.isEmpty())
                throw std::runtime_error("Invalid key file: 'KeyFile' element is empty.");

            reader.expectRead();

            while ((type = reader.nodeType()) != XML_READER_TYPE_END_ELEMENT){

                if (type == XML_READER_TYPE_ELEMENT &&
                        strcmp(reader.xlocalName().c_str(), "Key") == 0) break;

                reader.expectNext();
            }

            if (type != XML_READER_TYPE_ELEMENT)
                throw std::runtime_error("Invalid key file: 'KeyFile' element doesn't contain 'Key' element.");

            if (reader.isEmpty())
                throw std::runtime_error("Invalid key file: 'Key' element is empty.");

            reader.expectRead();

            while ((type = reader.nodeType()) != XML_READER_TYPE_END_ELEMENT){

                if (type == XML_READER_TYPE_ELEMENT &&
                        strcmp(reader.xlocalName().c_str(), "Data") == 0) break;

                reader.expectNext();
            }

            if (type != XML_READER_TYPE_ELEMENT)
                throw std::runtime_error("Invalid key file: 'Key' element doesn't contain 'Data' element.");
            if (reader.isEmpty())
                throw std::runtime_error("Invalid key file: 'Data' element is empty.");

            SafeString<char> keyData = reader.readString().c_str();
            if (keyData.size() <= 1) throw std::runtime_error("Key data too short.");
            return safeDecodeBase64(keyData);

        } catch (std::exception& e){
            std::stringstream s;
            s << "Error opening key file: '" << filename << "': " << e.what();
            throw std::runtime_error(s.str());
        }
    }

};

class BufferKey: public CompositeKey::Key{
private:
    SafeVector<uint8_t> keydata;
public:

    inline BufferKey(SafeVector<uint8_t> data) noexcept
        :Key(Type::Password),
          keydata(std::move(data))
    {}

    SafeVector<uint8_t> data() const override{
        return keydata;
    }
};

}

CompositeKey::Key::Ptr CompositeKey::Key::fromPassword(SafeString<char> pass){
    return Key::Ptr(new PasswordKey(std::move(pass)));
}

CompositeKey::Key::Ptr CompositeKey::Key::fromFile(SafeString<char> filename){
    return Key::Ptr(new FileKey(std::move(filename)));
}

CompositeKey::Key::Ptr CompositeKey::Key::fromBuffer(SafeVector<uint8_t> data){
    return Key::Ptr(new BufferKey(std::move(data)));
}

//-----------------------------------------------------------------------------------------------

SafeVector<uint8_t> CompositeKey::getCompositeKey(const std::array<uint8_t, 32>& transformSeed, uint64_t encryptionRounds) const{

    SafeVector<uint8_t> hash(32);
    OSSL::Digest d(EVP_sha256());

    for (const Key::Ptr& key: keys){
        d.update(key->data());
    }
    d.final(hash);

    //------

    const EVP_CIPHER* cipher = EVP_aes_256_ecb();
    if (EVP_CIPHER_key_length(cipher) != 32){
        std::ostringstream s;
        s << "AES with key size other than 32 bytes: " << EVP_CIPHER_key_length(cipher);
        throw std::runtime_error(s.str());
    }

    if (EVP_CIPHER_block_size(cipher) != 16){
        std::ostringstream s;
        s << "AES with block size other than 16 bytes: " << EVP_CIPHER_block_size(cipher);
        throw std::runtime_error(s.str());
    }

    //---------

    {
        const unsigned char iv[32] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                                      0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};

        OSSL::EvpCipher aes_cipher(cipher,
                                   nullptr,
                                   transformSeed.data(),
                                   iv,
                                   1);
        aes_cipher.set_padding(false);

        SafeVector<uint8_t> encryptedHash(32);

        for (uint64_t i=0; i<encryptionRounds; i++){
            int out = aes_cipher.update(encryptedHash.data(), hash.data(), 32);
            unused(out);
            assert(out == 32);
            using std::swap;
            swap(hash, encryptedHash);
        }

        int out = aes_cipher.final(encryptedHash.data());
        unused(out);
        assert(out == 0);
    }

    d.init(EVP_sha256());
    d.update(hash);
    d.final(hash);

    std::cout << "Composite key is: ";
    outHex(std::cout, &*hash.begin(), &*hash.end());
    std::cout << std::endl;

    return hash;
}

}

