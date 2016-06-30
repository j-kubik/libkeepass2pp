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

const std::array<uint8_t,32> hashInitBytes = {
    0xe8, 0x38, 0x82, 0x41,
    0xff, 0xba, 0x7e, 0xa1,
    0x77, 0x38, 0xbf, 0x93,
    0x4a, 0x4e, 0x45, 0xa2,
    0x95, 0xb4, 0x89, 0x56,
    0x4c, 0x7a, 0xf1, 0x7c,
    0xa2, 0x84, 0xb3, 0xce,
    0xef, 0x4d, 0xe6, 0x31
};

// Key:  c18b4f04dc8ad2b57202e40f4389dfea96fc82535ffa1e326a2561c96857e34f
// Iv:   d01f71601189889b5aab63a5ea2b6bdb
// Init: e8388241ffba7ea17738bf934a4e45a295b489564c7af17ca284b3ceef4de631

int main(int argc, char* argv[]){
    if (argc != 4){

        std::cout <<
        "Usage: " << argv[0] << " <command> <source file> <destination file>\n"
        "\n"
        "<command> can be a string that consists of following characters:\n"
        " d - deflate\n"
        " i - inflate\n"
        " e - encrypt using key: c18b4f04dc8ad2b57202e40f4389dfea96fc82535ffa1e326a2561c96857e34f\n"
        "     and iv: d01f71601189889b5aab63a5ea2b6bdb\n"
        " x - decrypt using key: c18b4f04dc8ad2b57202e40f4389dfea96fc82535ffa1e326a2561c96857e34f\n"
        "     and iv: d01f71601189889b5aab63a5ea2b6bdb\n"
        " h - hash stream using init bytes: e8388241ffba7ea17738bf934a4e45a295b489564c7af17ca284b3ceef4de631\n"
        " u - unhash stream using init bytes: e8388241ffba7ea17738bf934a4e45a295b489564c7af17ca284b3ceef4de631\n"
        " t - tee stream contents to file called 'tee.output'\n"
        "\n"
        "Examples:\n"
        "Takes input form f.in, defaltes it, inflates back and stores result in f.out file:\n"
        " " << argv[0] << " di f.in f.out \n"
        "Takes input form f.in, defaltes it, encrypts, decrypts back inflates back and stores result in f.out file:\n"
        " " << argv[0] << " dexi f.in f.out \n"
        << std::endl;
       return 2;
    }

    try{
        Pipeline pipeline;
        pipeline.setStart(std::unique_ptr<Pipeline::OutLink>(new IStreamLink(argv[2])));

        for (const char* process = argv[1]; *process; ++process){
            switch(*process){
            case 'd':
                pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new DeflateLink()));
                break;
            case 'i':
                pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new InflateLink()));
                break;
            case 'e':{
                OSSL::EvpCipher cipher(EVP_aes_256_cbc(),
                                       nullptr,
                                       encryptionKey.data(),
                                       encryptionIv.data(),
                                       1);
                cipher.set_padding(true);
                pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new EvpCipher(std::move(cipher))));
                break;
            }
            case 'x':{
                OSSL::EvpCipher cipher(EVP_aes_256_cbc(),
                                       nullptr,
                                       encryptionKey.data(),
                                       encryptionIv.data(),
                                       0);
                cipher.set_padding(true);
                pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new EvpCipher(std::move(cipher))));
                break;
            }
            case 'h':
                pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new HashStreamLink(hashInitBytes)));
                break;
            case 'u':
                pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new UnhashStreamLink(hashInitBytes)));
                break;

            case 't':
                pipeline.appendLink(std::unique_ptr<Pipeline::InOutLink>(new OStreamTeeLink("tee.output")));

            default:
                throw std::runtime_error("Unknown Pipeline node.");
            }
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





