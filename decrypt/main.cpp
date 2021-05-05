#include "AES_Decrypt.h"
#include <iostream>

using namespace std;


int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        cout << "‚È‚¢‚æ" << endl;
        return 0;
    }

    Decrypt* decrypt;
    decrypt = new Decrypt(argv[1], argv[3]);

    delete decrypt;
    return 0;
}