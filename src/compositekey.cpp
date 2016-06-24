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

CompositeKey::Key CompositeKey::Key::fromPassword(std::string passwd){
    OSSL::Digest d(EVP_sha256());
    d.update(passwd.data(), passwd.size());
    return Key(d.final(), Type::Password);

//	SHA256_CTX sha256;
//	SHA256_Init(&sha256);
//	SHA256_Update(&sha256, passwd.data(), passwd.size());
//	std::vector<uint8_t> key(32);
//	SHA256_Final(key.data(), &sha256);

//	return Key(key, Type::Password);
}

CompositeKey::Key CompositeKey::Key::fromFile(std::string filename){

	std::ifstream keyFile(filename);
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
		std::string localName = reader.xlocalName().c_str();
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

		std::string keyData = reader.readString().c_str();
		if (keyData.size() <= 1) throw std::runtime_error("Key data too short.");
		return Key(decodeBase64(keyData), Type::KeyFile);

	} catch (std::exception& e){
		std::stringstream s;
		s << "Error opening key file: '" << filename << "': " << e.what();
		throw std::runtime_error(s.str());
	}

}

//-----------------------------------------------------------------------------------------------

std::array<uint8_t, 32> CompositeKey::getCompositeKey(const std::array<uint8_t, 32>& transformSeed, uint64_t encryptionRounds) const{

	std::array<uint8_t, 32> hash;
    OSSL::Digest d(EVP_sha256());

    //SHA256_CTX sha256;
    //SHA256_Init(&sha256);
	for (const Key& key: keys){
        d.update(key.data());
        //SHA256_Update(&sha256, key.data().data(), key.data().size());
	}
    d.final(hash);
    //SHA256_Final(hash.data(), &sha256);

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
        OSSL::EvpCipherCtx aes_ctx;

		const unsigned char iv[32] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
									  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};

		if (EVP_EncryptInit_ex(aes_ctx, cipher, 0, transformSeed.data(), iv) == 0)
			throw std::runtime_error("Error initializing AES encryptor for password.");

		EVP_CIPHER_CTX_set_padding(aes_ctx, 0);

		std::array<uint8_t, 32> encryptedHash;
		int outl;

		for (uint64_t i=0; i<encryptionRounds; i++){

			if (EVP_EncryptUpdate(aes_ctx, encryptedHash.data(), &outl, hash.data(), 32) == 0)
				throw std::runtime_error("Error using AES encryptor for password.");
            assert(outl == 32);

			using std::swap;
			swap(hash, encryptedHash);
		}

		if (EVP_EncryptFinal_ex(aes_ctx, encryptedHash.data(), &outl) == 0)
			throw std::runtime_error("Error finishing AES encryptor for password.");

        assert(outl == 0);
	}

    d.init(EVP_sha256());
    d.update(hash);
    d.final(hash);

	return hash;
}

}

