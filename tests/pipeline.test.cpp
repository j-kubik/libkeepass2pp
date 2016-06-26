#include "../include/libkeepass2pp/links.h"

#include <fstream>
#include <cstring>

const std::array<uint8_t, 16> encryptionIv = {
    0xd0, 0x1f, 0x71, 0x60,
    0x11, 0x89, 0x88, 0x9b,
    0x5a, 0xab, 0x63, 0xa5,
    0xea, 0x2b, 0x6b, 0xdb};

const std::array<uint8_t, 32> encryptionKey = {
    0xc1, 0x8b, 0x4f, 0x04,
    0xdc, 0x8a, 0xd2, 0xb5,
    0x72, 0x02, 0xe4, 0x0f,
    0x43, 0x89, 0xdf, 0xea,
    0x96, 0xfc, 0x82, 0x53,
    0x5f, 0xfa, 0x1e, 0x32,
    0x6a, 0x25, 0x61, 0xc9,
    0x68, 0x57, 0xe3, 0x4f
};

// Key: c18b4f04dc8ad2b57202e40f4389dfea96fc82535ffa1e326a2561c96857e34f
// Iv:  d01f71601189889b5aab63a5ea2b6bdb

int main(int argc, char* argv[]){
    if (argc != 4)
        return 2;

    bool pack = (strcmp(argv[1], "pack") == 0);
    bool unpack = (strcmp(argv[1], "unpack") == 0);
    if (strcmp(argv[1], "both") == 0){
        pack = true;
        unpack = true;
    }

    try{
        Pipeline pipeline;
        pipeline.setStart(std::unique_ptr<Pipeline::OutLink>(new IStreamLink(argv[2])));

        if (pack){
            pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new DeflateLink()));

            std::unique_ptr<EvpCipher> cipher(new EvpCipher());
            if (EVP_CipherInit(cipher->context(), EVP_aes_256_cbc(), encryptionKey.data(), encryptionIv.data(), 1) == 0)
                return 2;
            EVP_CIPHER_CTX_set_padding(cipher->context(), 1);
            pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(std::move(cipher)));
        }

        if (unpack){
            std::unique_ptr<EvpCipher> cipher = std::unique_ptr<EvpCipher>(new EvpCipher());
            if (EVP_CipherInit(cipher->context(), EVP_aes_256_cbc(), encryptionKey.data(), encryptionIv.data(), 0) == 0)
                return 2;
            EVP_CIPHER_CTX_set_padding(cipher->context(), 1);
            pipeline.appendLink(std::move(cipher));
            pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new InflateLink()));
        }

        std::unique_ptr<OStreamLink> finish(new OStreamLink(argv[3]));
        auto future = finish->getFuture();
        pipeline.setFinish(std::move(finish));
        pipeline.run();

        future.get();

        return 0;
    }catch(std::exception& e){
        std::cerr << e.what() << std::endl;
        return 1;
    }


}





