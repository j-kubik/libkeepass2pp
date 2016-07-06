#include "../include/libkeepass2pp/cryptorandom.h"

#include <fstream>
#include <sstream>
#include <cstring>

int main(int argc, char* argv[]){
    if (argc != 3){

        std::cout <<
        "Usage: " << argv[0] << " <s|a> <key>\n"
        "Paramaters:\n"
        " s|a - Either s for Salsa20, or a for ArcFour;\n"
        " key - hex data to be used as initialization key\n"
        << std::endl;
        return 2;
    }

    try{

        Kdbx::RandomStream::Ptr stream;

        std::istringstream s(argv[2]);
        std::vector<uint8_t> key = inHex(argv[2], argv[2] + strlen(argv[2]));

        if (strcmp(argv[1], "a") == 0){
            stream = Kdbx::RandomStream::Ptr(new Kdbx::ArcFourVariant(SafeVector<uint8_t>(key.begin(), key.end())));
        } else if (strcmp(argv[1], "s") == 0){
            stream = Kdbx::RandomStream::Ptr(new Kdbx::Salsa20(SafeVector<uint8_t>(key.begin(), key.end())));
        } else {
            std::cerr << "Unknown random stream code: " << argv[1] << std::endl;
            return 2;
        }

        SafeVector<uint8_t> result = stream->read(2048);
        outHex(std::cout , result);
    }catch(std::exception& e){
        std::cerr << e.what() << std::endl;
        return 2;
    }
}

