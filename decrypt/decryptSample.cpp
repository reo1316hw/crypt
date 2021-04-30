#include <iostream>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#define Block 1

using namespace std;
void decode(char* dst);
int main()
{

    string fileName;    //ファイル名


    //ファイル名からバイナリファイルで読み込む
    cout << "復号化するファイル名を入力してください\n";
    //キーボード入力からファイル名を取得する
    getline(cin, fileName);
    ifstream ifs(fileName, ios::binary);

    string outFileName; //ファイル名
    //ofstreamを読み取りモードで開き、末尾に移動
    cout << "出力するファイル名を入力してください\n";
    //キーボード入力からファイル名を取得する
    getline(cin, outFileName);
    ofstream ofs(outFileName, ios::app | ios::binary);

    //読み込みデータ
    char data[Block];

    //初期化ベクトル
    char initialData[Block];
    memset(initialData, 'I', Block);

    //一時保存読み込みデータ
    char dataTemp[Block];

    //1つ前の暗号ブロック
    char cipherBlockPre[Block];

    //復号ブロック
    char decodeBlock[Block];

    //データ読込
    ifs.read(data, Block);

    //1つ前の暗号ブロックに暗号化されているブロックを格納
    memcpy(cipherBlockPre, data, Block);

    //復号化
    decode(data);
    //ブロック長ごとに処理
    for (int i = 0; i < Block; i++)
    {
        decodeBlock[i] = data[i] ^ initialData[i];
    }
    //暗号化したブロックを出力
    ofs.write(decodeBlock, Block);
    do {
        //データ読込
        ifs.read(data, Block);
        memcpy(dataTemp, data, Block);
        //復号化
        decode(data);
        //データがなかった場合終了する。
        if (ifs.eof()) break;
        //ブロック長ごとに処理
        for (int i = 0; i < Block; i++)
        {
            decodeBlock[i] = data[i] ^ cipherBlockPre[i];
        }

        //暗号化したブロックを出力
        ofs.write(decodeBlock, Block);

        //1つ前の暗号ブロックに暗号化されているブロックを格納
        memcpy(cipherBlockPre, dataTemp, Block);
    } while (true);

}

//復号化
void decode(char* dst)
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