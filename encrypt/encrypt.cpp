//�Q�l��
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
    string fileName;    //�t�@�C����

    //�t�@�C��������o�C�i���t�@�C���œǂݍ���
    std::cout << "�Í�������t�@�C��������͂��Ă�������\n";
    //�L�[�{�[�h���͂���t�@�C�������擾����
    getline(cin, fileName);
    std::ifstream ifs(fileName, std::ios::binary);

    string outFileName; //�t�@�C����
    //ofstream��ǂݎ�胂�[�h�ŊJ���A�����Ɉړ�
    std::cout << "�o�͂���t�@�C��������͂��Ă�������\n";
    //�L�[�{�[�h���͂���t�@�C�������擾����
    getline(cin, outFileName);
    std::ofstream ofs(outFileName, std::ios::app | std::ios::binary);

    //�ǂݍ��݃f�[�^
    char data[Block];

    //�������x�N�g��
    char initialData[Block];
    memset(initialData, 'I', Block);

    //1�O�̈Í��u���b�N
    char cipherBlockPre[Block];

    //�Í��u���b�N
    char cipherBlock[Block];

    //�f�[�^�Ǎ�
    ifs.read(data, Block);
    //�u���b�N�����Ƃɏ���
    for (int i = 0; i < Block; i++)
    {
        cipherBlock[i] = data[i] ^ initialData[i];
    }

    //�Í���
    cipher(cipherBlock);
    //�Í��������u���b�N���o��
    ofs.write(cipherBlock, Block);
    //1�O�̈Í��u���b�N�ɈÍ��������u���b�N���i�[
    memcpy(cipherBlockPre, cipherBlock, Block);
    do {
        //�f�[�^�Ǎ�
        ifs.read(data, Block);
        //�f�[�^���Ȃ������ꍇ�I������B
        if (ifs.eof()) break;
        //�u���b�N�����Ƃɏ���
        for (int i = 0; i < Block; i++)
        {
            cipherBlock[i] = data[i] ^ cipherBlockPre[i];
        }
        //�Í���
        cipher(cipherBlock);
        //�Í��������u���b�N���o��
        ofs.write(cipherBlock, Block);
        //1�O�̈Í��u���b�N�ɈÍ��������u���b�N���i�[
        memcpy(cipherBlockPre, cipherBlock, Block);
    } while (true);

}

void cipher(char* dst)
{
    //�Í���
    char cipherBlockTemp[Block];
    memset(cipherBlockTemp, 'S', Block);
    //�u���b�N�����Ƃɏ���
    for (int i = 0; i < Block; i++)
    {
        //XOR�Í�
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
//    int key = 12345; //�C�ӂ̈Í����L�[
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
//    /*printf("�����l=%d\n", str);
//    crypt = str ^ key;
//    printf("�Í���=%d\n", crypt);
//    crypt = crypt ^ key;
//    printf("������=%d\n", crypt);*/
//    return 0;
//}

//unsigned char cipherText;
///* �Í�������֐� */
//unsigned char encrypt(unsigned char plainText, unsigned char key, unsigned char iv, enum cipherMode)
//{
//    // key��iv��cipherMode���g����plainText�������Ⴎ����ɂ��������鏈��������
//    // ...
//
//    // �Í������o���オ��
//    return cipherText;
//}