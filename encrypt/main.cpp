#include "AES_Encrypt.h"

bool ErrorHandling(int argc, char* argv[])
{
    string commandLine1 = "-i";
    string commandLine3 = "-o";

    //if (argc <= 1)
    //{
    //    cout << "�R�}���h���C������������܂���" << endl;
    //    return true;
    //}

    //if (argc >= 6)
    //{
    //    cout << "�R�}���h���C���������������܂�" << endl;
    //    return true;
    //}

    //if (argv[1] != commandLine1)
    //{
    //    cout << "1�Ԗڂ̃R�}���h���C��������'-i'�Ŏw�肵�Ă�������" << endl;
    //    return true;
    //}

    //if (argv[3] != commandLine3)
    //{
    //    cout << "3�Ԗڂ̃R�}���h���C��������'-o'�Ŏw�肵�Ă�������" << endl;
    //    return true;
    //}

    return false;
}

int main(int argc, char* argv[])
{
    if (ErrorHandling(argc, argv))
    {
        return 0;
    }

    int keyLength;
    cout << "���ʌ��̒������w�肵�Ă�������(4�A6�A8�̂����ꂩ����͂��Ă�������)" << endl;
    cin >> keyLength;

    Encrypt encrypt(argv[2], argv[4], keyLength);

    return 0;
}