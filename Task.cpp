#include<iostream>
#include<fstream>
#include<string>
#include<cstdlib>

using namespace std;

//�Q�l��
//https://www.trustss.co.jp/cng/1000.html

//// ���f�[�^������
//void InitKey(byte* key, size_t size) {
//    for (size_t i = 0; i < size; ++i) {
//        key[i] = rand();
//    }
//}

int main(int argc, char** argv) {

    //// ���ʌ��EIV
    //byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    //byte iv[CryptoPP::AES::BLOCKSIZE];

    //// ���ʌ���IV��K���Ȓl�ŏ�����
    //InitKey(key, sizeof(key));
    //InitKey(iv, sizeof(iv));

    //�t�@�C���̑I���ƃI�[�v��
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

    //string plainText = str3; //    string plainText = "�Í��������O�̕�����"+str3;

    //cout << "Plain Text : " << plainText << endl;


    // �Í����I�u�W�F�N�g�̍쐬
    ////CryptoPP::CTR_Mode<cryptoPP::AES>::Encryption enc;
    //CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
    //enc.SetKeyWithIV(key, sizeof(key), iv);

    //// �Í����̂��߂̕ϊ��t�B���^�̍쐬
    //string encText;
    //CryptoPP::StreamTransformationFilter encFilter(enc, new CryptoPP::StringSink(encText));

    //// �Í���
    //encFilter.Put(reinterpret_cast<const byte*>(plainText.c_str()), plainText.size());
    //encFilter.MessageEnd();

    //cout << "Encrypted Text : " << encText << std::endl;


    ////�Í����e�L�X�g���t�@�C���ɓ����B
    //file1.open(str);
    //if (!file1.is_open()) {
    //    return EXIT_FAILURE;
    //}
    //file1 << encText << endl;
    //file1.close();


    //// �������I�u�W�F�N�g�̍쐬
    //CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
    //dec.SetKeyWithIV(key, sizeof(key), iv);

    //// �������̂��߂̕ϊ��t�B���^�̍쐬
    //std::string decText;
    //CryptoPP::StreamTransformationFilter decFilter(dec, new CryptoPP::StringSink(decText));
    //decFilter.Put(reinterpret_cast<const byte*>(encText.c_str()), encText.size());
    //decFilter.MessageEnd();

    //cout << "Decrypted Text : " << decText << std::endl;

    ////�������e�L�X�g���t�@�C���ɓ����B
    //file1.open(str);
    //if (!file1.is_open()) {
    //    return EXIT_FAILURE;
    //}
    //file1 << decText << endl;
    //file1.close();



    return 0;

}