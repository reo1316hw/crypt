#include "Decrypt.h"

int main(int argc, char* argv[])
{
    Decrypt* decrypt;
    decrypt = new Decrypt(argv);

    delete decrypt;
    return 0;
}