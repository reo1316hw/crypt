//参考元
//https://www.hiramine.com/programming/windows/encryptdecryptstring_aes128ecb.html
//https://www.trustss.co.jp/cng/1000.html
//https://programming-place.net/ppp/contents/algorithm/other/003.html
//https://moba1.hatenablog.com/entry/2019/12/04/024145
//https://qiita.com/asksaito/items/1793b8d8b3069b0b8d68

//https://qiita.com/p1ro3/items/6bb1c78a6c27109f6b93

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#define Block 1

using namespace std;
void cipher(char* dst);

int main()
{
    string fileName;    //ファイル名

    //ファイル名からバイナリファイルで読み込む
    std::cout << "暗号化するファイル名を入力してください\n";
    //キーボード入力からファイル名を取得する
    getline(cin, fileName);
    std::ifstream ifs(fileName, std::ios::binary);

    string outFileName; //ファイル名
    //ofstreamを読み取りモードで開き、末尾に移動
    std::cout << "出力するファイル名を入力してください\n";
    //キーボード入力からファイル名を取得する
    getline(cin, outFileName);
    std::ofstream ofs(outFileName, std::ios::app | std::ios::binary);

    //読み込みデータ
    char data[Block];

    //初期化ベクトル
    char initialData[Block];
    memset(initialData, 'I', Block);

    //1つ前の暗号ブロック
    char cipherBlockPre[Block];

    //暗号ブロック
    char cipherBlock[Block];

    //データ読込
    ifs.read(data, Block);
    //ブロック長ごとに処理
    for (int i = 0; i < Block; i++)
    {
        cipherBlock[i] = data[i] ^ initialData[i];
    }

    //暗号化
    cipher(cipherBlock);
    //暗号化したブロックを出力
    ofs.write(cipherBlock, Block);
    //1つ前の暗号ブロックに暗号化したブロックを格納
    memcpy(cipherBlockPre, cipherBlock, Block);
    do {
        //データ読込
        ifs.read(data, Block);
        //データがなかった場合終了する。
        if (ifs.eof()) break;
        //ブロック長ごとに処理
        for (int i = 0; i < Block; i++)
        {
            cipherBlock[i] = data[i] ^ cipherBlockPre[i];
        }
        //暗号化
        cipher(cipherBlock);
        //暗号化したブロックを出力
        ofs.write(cipherBlock, Block);
        //1つ前の暗号ブロックに暗号化したブロックを格納
        memcpy(cipherBlockPre, cipherBlock, Block);
    } while (true);

}

void cipher(char* dst)
{
    //暗号鍵
    char cipherBlockTemp[Block];
    memset(cipherBlockTemp, 'S', Block);
    //ブロック長ごとに処理
    for (int i = 0; i < Block; i++)
    {
        //XOR暗号
        dst[i] = dst[i] ^ cipherBlockTemp[i];
    }
    return;
}

//#include <iostream>
//#include <iostream>
//#include <fstream>
//#include <string>
//
//using namespace std;
//
//int main(void)
//{
//    fstream file1,file2;
//    string str1, str2, str3;
//    int key = 12345; //任意の暗号化キー
//    int crypt;
//
//    str1 = "heart.png";
//
//    file1.open(str1, ios::binary | ios::in);
//    if (!file1.is_open()) {
//        return EXIT_FAILURE;
//    }
//
//   /* while (!file1.eof())
//    {
//        file1 >> str2;
//        str2 += '\n';
//        str3 += str2;
//    }*/
//
//    file1.close();
//
//    //cout << str3 << endl;
//   
//    /*printf("初期値=%d\n", str);
//    crypt = str ^ key;
//    printf("暗号化=%d\n", crypt);
//    crypt = crypt ^ key;
//    printf("複合化=%d\n", crypt);*/
//    return 0;
//}

//unsigned char cipherText;
///* 暗号化する関数 */
//unsigned char encrypt(unsigned char plainText, unsigned char key, unsigned char iv, enum cipherMode)
//{
//    // keyとivとcipherModeを使ってplainTextをぐちゃぐちゃにかき混ぜる処理をする
//    // ...
//
//    // 暗号文が出来上がる
//    return cipherText;
//}