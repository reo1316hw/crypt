#include "Encrypt.h"

int main(int argc, char* argv[])
{
    Encrypt* encrypt;
    encrypt = new Encrypt(argv);

    delete encrypt;
    return 0;
}