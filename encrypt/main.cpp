#include "Encrypt.h"
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
   /* if (argc <= 1)
    {
        cout << "‚È‚¢‚æ" << endl;
        return 0;
    }

    cout << argv[1] << endl;*/

    Encrypt* encrypt;
    encrypt = new Encrypt(argv);

    delete encrypt;
    return 0;
}