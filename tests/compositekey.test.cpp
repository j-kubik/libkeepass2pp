#include "../include/libkeepass2pp/compositekey.h"

#include <fstream>
#include <sstream>
#include <cstring>

int main(int argc, char* argv[]){
    if (argc == 1){

        std::cout <<
        "Usage: " << argv[0] << " <-f key_file> <-p pass> <-r rounds> <-t seed>\n"
        "Paramaters:\n"
        " -f KeePass 2 key file;\n"
        " -p password\n"
        " -r transform rounds (default=6000)\n"
        " -t transform seed (32 bytes in hex, default all zeroes)\n"
        "\n" << std::endl;
        return 2;
    }

    try{

        Kdbx::CompositeKey key;
        uint64_t transformRounds = 6000;
        std::array<uint8_t, 32> transformSeed = {0,0,0,0,0,0,0,0,
                                                 0,0,0,0,0,0,0,0,
                                                 0,0,0,0,0,0,0,0,
                                                 0,0,0,0,0,0,0,0};

        --argc;
        for (int i=1; i<argc; ++i){
            if (strcmp(argv[i], "-f") == 0){
                ++i;
                key.addKey(Kdbx::CompositeKey::Key::fromFile(argv[i]));
            }else if (strcmp(argv[i], "-p") == 0){
                ++i;
                key.addKey(Kdbx::CompositeKey::Key::fromPassword(argv[i]));
            }else if (strcmp(argv[i], "-r") == 0){
                ++i;
                std::istringstream s(argv[i]);
                uint64_t tmp;
                s >> tmp;
                if (s.good()){
                    transformRounds = tmp;
                }else{
                    std::cout << "Bad value to -r paramter (must be an integer)." << std::endl;
                    return 1;
                }

            }else if (strcmp(argv[i], "-t") == 0){
                ++i;
                std::istringstream s(argv[i]);
                inHex(s, transformSeed);
            }

        }

        auto result = key.getCompositeKey(transformSeed, transformRounds);
        outHex(std::cout, &*result.begin(), &*result.end());
        std::cout << std::endl;
    }catch(std::exception& e){
        std::cerr << e.what() << std::endl;
        return 2;
    }
}

