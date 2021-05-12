#include "AES_Encrypt.h"

bool ErrorHandling(int argc, char* argv[])
{
    string commandLine1 = "-i";
    string commandLine3 = "-o";

    //if (argc <= 1)
    //{
    //    cout << "コマンドライン引数がありません" << endl;
    //    return true;
    //}

    //if (argc >= 6)
    //{
    //    cout << "コマンドライン引数が多すぎます" << endl;
    //    return true;
    //}

    //if (argv[1] != commandLine1)
    //{
    //    cout << "1番目のコマンドライン引数は'-i'で指定してください" << endl;
    //    return true;
    //}

    //if (argv[3] != commandLine3)
    //{
    //    cout << "3番目のコマンドライン引数は'-o'で指定してください" << endl;
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
    cout << "共通鍵の長さを指定してください(4、6、8のいずれかを入力してください)" << endl;
    cin >> keyLength;

    Encrypt encrypt(argv[2], argv[4], keyLength);

    return 0;
}