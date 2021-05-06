#include "AES_Decrypt.h"

Decrypt::Decrypt(char* _inputFileName, char* _outputFileName)
{
    memcpy(key, keys, 16);
    nk = 4;               //���̒��� 4,6,8(128,192,256 bit)
    nr = nk + 6;          //���E���h�� 10,12,14

    //�Í������邽�߂̌��̏���
    KeyExpansion(key);
    //���̓t�@�C�����J������
    bool practicable = OpenInputFile(_inputFileName);
    //�������ނ��߂̏o�̓t�@�C���𐶐�
    ofs = new ofstream(_outputFileName, ios::app | ios::binary);

    //���̓t�@�C�����J���ꂽ�珑�����ݏ������s��
    if (practicable)
    {
        //�����1�u���b�N���̕����f�[�^����������
        InitWritingDecryptData();
        //EOF�܂ŕ��������f�[�^����������
        WritingDecryptData();
    }
    else
    {
        return;
    }

    practicable = false;
}

Decrypt::~Decrypt()
{
    delete ifs;
    delete ofs;
}

bool Decrypt::OpenInputFile(char* _inputFileName)
{
    //�t�@�C��������o�C�i���t�@�C���œǂݍ���
    ifs = new ifstream(_inputFileName, ios::binary);

    if (ifs)
    {
        return true;
    }
    else
    {
        cout << "�t�@�C�����J���܂���ł���" << endl;
        return false;
    }
}

/**
 * @fn �����1�u���b�N���̕����f�[�^����������
 */
void Decrypt::InitWritingDecryptData()
{
    memset(initialData, 'I', NBb);

    //�f�[�^�Ǎ�
    ifs->read((char*)data, NBb);

    //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
    memcpy(cipherBlockPre, data, NBb);

    //����
    InvCipher(data);

    //�u���b�N�����Ƃɏ���
    for (int i = 0; i < NB; i++)
    {
        decryptBlock[i] = data[i] ^ initialData[i];
    }

    //���������u���b�N���o��
    ofs->write((char*)decryptBlock, NBb);
}

/**
 * @fn EOF�܂ŕ��������f�[�^����������
 */
void Decrypt::WritingDecryptData()
{
    //�f�[�^���Ȃ������ꍇ�I������B
    while (ifs->eof())
    {
        //�f�[�^�Ǎ�
        ifs->read((char*)data, NBb);

        memcpy(dataTemp, data, NBb);

        //����
        InvCipher(data);

        //�u���b�N�����Ƃɏ���
        for (int i = 0; i < NB; i++)
        {
            decryptBlock[i] = data[i] ^ cipherBlockPre[i];
        }

        //���������u���b�N���o��
        ofs->write((char*)decryptBlock, NBb);

        //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
        memcpy(cipherBlockPre, dataTemp, NBb);
    }
}


//������
int Decrypt::InvCipher(int* _data)
{
    int i;

    AddRoundKey(_data, nr);

    for (i = nr - 1; i > 0; i--)
    {
        InvShiftRows(_data);
        InvSubBytes(_data);
        AddRoundKey(_data, i);
        InvMixColumns(_data);
    }

    InvShiftRows(_data);
    InvSubBytes(_data);
    AddRoundKey(_data, 0);
    return(nr);
}

void Decrypt::InvSubBytes(int* _data)
{
    int i, j;
    unsigned char* cb = (unsigned char*)_data;
    for (i = 0; i < NBb; i += 4)//���_�I�ȈӖ������d���[�v�ɂ��Ă��邪�Ӗ��͖���
    {
        for (j = 0; j < 4; j++)
        {
            cb[i + j] = invSbox[cb[i + j]];
        }
    }
}

void Decrypt::InvShiftRows(int* _data)
{
    int i, j, i4;
    unsigned char* cb = (unsigned char*)_data;
    unsigned char cw[NBb];
    memcpy(cw, cb, sizeof(cw));
    for (i = 0; i < NB; i += 4)
    {
        i4 = i * 4;
        for (j = 1; j < 4; j++)
        {
            cw[i4 + j + ((j + 0) & 3) * 4] = cb[i4 + j + 0 * 4];
            cw[i4 + j + ((j + 1) & 3) * 4] = cb[i4 + j + 1 * 4];
            cw[i4 + j + ((j + 2) & 3) * 4] = cb[i4 + j + 2 * 4];
            cw[i4 + j + ((j + 3) & 3) * 4] = cb[i4 + j + 3 * 4];
        }
    }
    memcpy(cb, cw, sizeof(cw));
}

int Decrypt::Mul(int _dt, int _n)
{
    int i, x = 0;
    for (i = 8; i > 0; i >>= 1)
    {
        x <<= 1;
        if (x & 0x100)
            x = (x ^ 0x1b) & 0xff;
        if ((_n & i))
            x ^= _dt;
    }
    return(x);
}

int Decrypt::Dataget(void* _data, int _n)
{
    return(((unsigned char*)_data)[_n]);
}

void Decrypt::InvMixColumns(int* _data)
{
    int i, i4, x;
    for (i = 0; i < NB; i++)
    {
        i4 = i * 4;
        x = Mul(Dataget(_data, i4 + 0), 14) ^
            Mul(Dataget(_data, i4 + 1), 11) ^
            Mul(Dataget(_data, i4 + 2), 13) ^
            Mul(Dataget(_data, i4 + 3), 9);
        x |= (Mul(Dataget(_data, i4 + 1), 14) ^
            Mul(Dataget(_data, i4 + 2), 11) ^
            Mul(Dataget(_data, i4 + 3), 13) ^
            Mul(Dataget(_data, i4 + 0), 9)) << 8;
        x |= (Mul(Dataget(_data, i4 + 2), 14) ^
            Mul(Dataget(_data, i4 + 3), 11) ^
            Mul(Dataget(_data, i4 + 0), 13) ^
            Mul(Dataget(_data, i4 + 1), 9)) << 16;
        x |= (Mul(Dataget(_data, i4 + 3), 14) ^
            Mul(Dataget(_data, i4 + 0), 11) ^
            Mul(Dataget(_data, i4 + 1), 13) ^
            Mul(Dataget(_data, i4 + 2), 9)) << 24;
        _data[i] = x;
    }
}

/************************************************************/
/* FIPS 197  P.19 Figure 10 */
void Decrypt::AddRoundKey(int* _data, int _n)
{
    int i;
    for (i = 0; i < NB; i++)
    {
        _data[i] ^= w[i + NB * _n];
    }
}

int Decrypt::SubWord(int _in)
{
    int inw = _in;
    unsigned char* cin = (unsigned char*)&inw;
    cin[0] = Sbox[cin[0]];
    cin[1] = Sbox[cin[1]];
    cin[2] = Sbox[cin[2]];
    cin[3] = Sbox[cin[3]];
    return(inw);
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
int Decrypt::RotWord(int _in)
{
    int inw = _in, inw2 = 0;
    unsigned char* cin = (unsigned char*)&inw;
    unsigned char* cin2 = (unsigned char*)&inw2;
    cin2[0] = cin[1];
    cin2[1] = cin[2];
    cin2[2] = cin[3];
    cin2[3] = cin[0];
    return(inw2);
}

void Decrypt::KeyExpansion(void* _key)
{
    /* FIPS 197  P.27 Appendix A.1 Rcon[i/Nk] */ //���� mul���g�p����
    int Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
    int i, temp;

    memcpy(w, _key, nk * 4);
    for (i = nk; i < NB * (nr + 1); i++)
    {
        temp = w[i - 1];
        if ((i % nk) == 0)
            temp = SubWord(RotWord(temp)) ^ Rcon[(i / nk) - 1];
        else if (nk > 6 && (i % nk) == 4)
            temp = SubWord(temp);
        w[i] = w[i - nk] ^ temp;
    }
}