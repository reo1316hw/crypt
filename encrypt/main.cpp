#include "AES_Encrypt.h"
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        cout << "�Ȃ���" << endl;
        return 0;
    }

    Encrypt* encrypt;
    encrypt = new Encrypt(argv[2], argv[4]);

    delete encrypt;
    return 0;
}