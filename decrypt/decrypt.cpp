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

    string fileName;    //�t�@�C����


    //�t�@�C��������o�C�i���t�@�C���œǂݍ���
    std::cout << "����������t�@�C��������͂��Ă�������\n";
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

    //�ꎞ�ۑ��ǂݍ��݃f�[�^
    char dataTemp[Block];

    //1�O�̈Í��u���b�N
    char cipherBlockPre[Block];

    //�����u���b�N
    char decodeBlock[Block];

    //�f�[�^�Ǎ�
    ifs.read(data, Block);
    //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
    memcpy(cipherBlockPre, data, Block);
    //������
    decode(data);
    //�u���b�N�����Ƃɏ���
    for (int i = 0; i < Block; i++)
    {
        decodeBlock[i] = data[i] ^ initialData[i];
    }
    //�Í��������u���b�N���o��
    ofs.write(decodeBlock, Block);
    do {
        //�f�[�^�Ǎ�
        ifs.read(data, Block);
        //�f�[�^���Ȃ������ꍇ�I������B
        memcpy(dataTemp, data, Block);
        //������
        decode(data);
        if (ifs.eof()) break;
        //�u���b�N�����Ƃɏ���
        for (int i = 0; i < Block; i++)
        {
            decodeBlock[i] = data[i] ^ cipherBlockPre[i];
        }
        //�Í��������u���b�N���o��
        ofs.write(decodeBlock, Block);
        //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
        memcpy(cipherBlockPre, dataTemp, Block);
    } while (true);
    //

}

//������
void decode(char* dst)
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