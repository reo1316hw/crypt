#include "AES_Decrypt.h"

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        cout << "‚È‚¢‚æ" << endl;
        return 0;
    }

    Decrypt decrypt(argv[2], argv[4]);

    return 0;
}