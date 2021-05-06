#include "AES_Encrypt.h"
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        cout << "‚È‚¢‚æ" << endl;
        return 0;
    }

    Encrypt encrypt(argv[2], argv[4]);

    return 0;
}