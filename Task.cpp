#include<iostream>
#include<fstream>
#include<string>
#include<cstdlib>

using namespace std;

//参考元
//https://www.trustss.co.jp/cng/1000.html

//// 鍵データ初期化
//void InitKey(byte* key, size_t size) {
//    for (size_t i = 0; i < size; ++i) {
//        key[i] = rand();
//    }
//}

int main(int argc, char** argv) {

    //// 共通鍵・IV
    //byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    //byte iv[CryptoPP::AES::BLOCKSIZE];

    //// 共通鍵とIVを適当な値で初期化
    //InitKey(key, sizeof(key));
    //InitKey(iv, sizeof(iv));

    //ファイルの選択とオープン
    fstream file1, file2;
    string str, str2, str3;

    str = "heart.png";

    file1.open(str, ios::binary | ios::in);
    if (!file1.is_open()) {
        return EXIT_FAILURE;
    }

    while (!file1.eof())
    {
        file1 >> str2;
        str3 += str2;
        file2 << str3;
    }

    //for (int i = 0; i < 5; i++)   str3.pop_back();

    file1.close();
    //file2.close();
    cout << str3 << endl;

    //string plainText = str3; //    string plainText = "暗号化される前の平文＝"+str3;

    //cout << "Plain Text : " << plainText << endl;


    // 暗号化オブジェクトの作成
    ////CryptoPP::CTR_Mode<cryptoPP::AES>::Encryption enc;
    //CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
    //enc.SetKeyWithIV(key, sizeof(key), iv);

    //// 暗号化のための変換フィルタの作成
    //string encText;
    //CryptoPP::StreamTransformationFilter encFilter(enc, new CryptoPP::StringSink(encText));

    //// 暗号化
    //encFilter.Put(reinterpret_cast<const byte*>(plainText.c_str()), plainText.size());
    //encFilter.MessageEnd();

    //cout << "Encrypted Text : " << encText << std::endl;


    ////暗号化テキストをファイルに入れる。
    //file1.open(str);
    //if (!file1.is_open()) {
    //    return EXIT_FAILURE;
    //}
    //file1 << encText << endl;
    //file1.close();


    //// 復号化オブジェクトの作成
    //CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
    //dec.SetKeyWithIV(key, sizeof(key), iv);

    //// 復号化のための変換フィルタの作成
    //std::string decText;
    //CryptoPP::StreamTransformationFilter decFilter(dec, new CryptoPP::StringSink(decText));
    //decFilter.Put(reinterpret_cast<const byte*>(encText.c_str()), encText.size());
    //decFilter.MessageEnd();

    //cout << "Decrypted Text : " << decText << std::endl;

    ////復号化テキストをファイルに入れる。
    //file1.open(str);
    //if (!file1.is_open()) {
    //    return EXIT_FAILURE;
    //}
    //file1 << decText << endl;
    //file1.close();



    return 0;

}