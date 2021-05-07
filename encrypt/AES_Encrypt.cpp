#include "AES_Encrypt.h"

Encrypt::Encrypt(char* _inputFileName, char* _outputFileName)
{
    //���̓t�@�C�����J������
    bool practicable = OpenInputFile(_inputFileName);
    //�������ނ��߂̏o�̓t�@�C���𐶐�
    ofs = new ofstream(_outputFileName, ios::app | ios::binary);

    memcpy(key, keys, 16);
    nk = 4;               //���̒��� 4,6,8(128,192,256 bit)
    nr = nk + 6;          //���E���h�� 10,12,14

    //�Í������邽�߂̌��̏���
    KeyExpansion(key);

    //���̓t�@�C�����J���ꂽ�珑�����ݏ������s��
    if (practicable)
    {
        //�����1�u���b�N���̈Í����f�[�^����������
        InitWritingEncryptData();
        //EOF�܂ňÍ��������f�[�^����������
        WritingEncryptData();
    }
    //���̓t�@�C�����J���Ȃ������珑�����ݏ������s��Ȃ�
    else
    {
        return;
    }

    practicable = false;
}

Encrypt::~Encrypt()
{
    delete ifs;
    delete ofs;
}

/**
 * @fn ���̓t�@�C�����J��
 * @param _inputFileName ���̓t�@�C����
 * @return true : �J����, false : �J���Ȃ�����
 */
bool Encrypt::OpenInputFile(char* _inputFileName)
{
    //�t�@�C��������o�C�i���t�@�C���œǂݍ���
    ifs = new ifstream(_inputFileName, ios::binary);

    //�t�@�C�����J������true��Ԃ�
    if (ifs)
    {
        return true;
    }
    //�t�@�C�����J���Ȃ�������false��Ԃ�
    else
    {
        cout << "�t�@�C�����J���܂���ł���" << endl;
        return false;
    }
}

void Encrypt::InitWritingEncryptData()
{
    //�������x�N�g���̒��g��S��"I" = 0x49�ɂ���
    memset(initialData, 'I', NBb);

    //�ŏ���1�u���b�N���f�[�^�Ǎ�
    ifs->read((char*)data, NBb);

    //�Í��u���b�N�ɓǂݍ��񂾃f�[�^��n�o�C�g��XOR���đ��(n = �o�C�g��)
    for (int i = 0; i < NB; i++)
    {
        encryptBlock[i] = data[i] ^ initialData[i];
    }

    //�ŏ���1�u���b�N���Í���
    Cipher(encryptBlock);

    //�Í��������ŏ���1�u���b�N����������
    ofs->write((char*)encryptBlock, NBb);

    //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
    memcpy(cipherBlockPre, encryptBlock, NBb);
}

void Encrypt::WritingEncryptData()
{
    //�f�[�^���Ȃ������ꍇ�I������B
    while (ifs->eof())
    {
        //1�u���b�N���f�[�^�Ǎ�
        ifs->read((char*)data, NBb);

        //�u���b�N�����Ƃɏ���
        //�Í��u���b�N�ɓǂݍ��񂾃f�[�^��n�o�C�g��XOR���đ��(n = �o�C�g��)
        for (int i = 0; i < NB; i++)
        {
            encryptBlock[i] = data[i] ^ cipherBlockPre[i];
        }

        //1�u���b�N���Í���
        Cipher(encryptBlock);

        //�Í�������1�u���b�N����������
        ofs->write((char*)encryptBlock, NBb);

        //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
        memcpy(cipherBlockPre, encryptBlock, NBb);
    }
}

//�Í���
int Encrypt::Cipher(int* _data)
{
    int i;

    AddRoundKey(_data, 0);

    for (i = 1; i < nr; i++)
    {
        SubBytes(_data);
        ShiftRows(_data);
        MixColumns(_data);
        AddRoundKey(_data, i);
    }

    SubBytes(_data);
    ShiftRows(_data);
    AddRoundKey(_data, i);
    return(i);
}

void Encrypt::SubBytes(int* _data)
{
    int i, j;
    unsigned char* cb = (unsigned char*)_data;
    for (i = 0; i < NBb; i += 4)//���_�I�ȈӖ������d���[�v�ɂ��Ă��邪�Ӗ��͖���
    {
        for (j = 0; j < 4; j++)
        {
            cb[i + j] = Sbox[cb[i + j]];
        }
    }
}

void Encrypt::ShiftRows(int* _data)
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
            cw[i4 + j + 0 * 4] = cb[i4 + j + ((j + 0) & 3) * 4];
            cw[i4 + j + 1 * 4] = cb[i4 + j + ((j + 1) & 3) * 4];
            cw[i4 + j + 2 * 4] = cb[i4 + j + ((j + 2) & 3) * 4];
            cw[i4 + j + 3 * 4] = cb[i4 + j + ((j + 3) & 3) * 4];
        }
    }

    memcpy(cb, cw, sizeof(cw));
}

//��Z (n�{) 
int Encrypt::Mul(int _dt, int _n)
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

int Encrypt::Dataget(void* _data, int _n)
{
    return(((unsigned char*)_data)[_n]);
}

void Encrypt::MixColumns(int* _data)
{
    int i, i4, x;
    for (i = 0; i < NB; i++)
    {
        i4 = i * 4;
        x = Mul(Dataget(_data, i4 + 0), 2) ^
            Mul(Dataget(_data, i4 + 1), 3) ^
            Mul(Dataget(_data, i4 + 2), 1) ^
            Mul(Dataget(_data, i4 + 3), 1);
        x |= (Mul(Dataget(_data, i4 + 1), 2) ^
            Mul(Dataget(_data, i4 + 2), 3) ^
            Mul(Dataget(_data, i4 + 3), 1) ^
            Mul(Dataget(_data, i4 + 0), 1)) << 8;
        x |= (Mul(Dataget(_data, i4 + 2), 2) ^
            Mul(Dataget(_data, i4 + 3), 3) ^
            Mul(Dataget(_data, i4 + 0), 1) ^
            Mul(Dataget(_data, i4 + 1), 1)) << 16;
        x |= (Mul(Dataget(_data, i4 + 3), 2) ^
            Mul(Dataget(_data, i4 + 0), 3) ^
            Mul(Dataget(_data, i4 + 1), 1) ^
            Mul(Dataget(_data, i4 + 2), 1)) << 24;
        _data[i] = x;
    }
}

void Encrypt::AddRoundKey(int* _data, int _n)
{
    int i;
    for (i = 0; i < NB; i++)
    {
        _data[i] ^= w[i + NB * _n];
    }
}

int Encrypt::SubWord(int _in)
{
    int inw = _in;
    unsigned char* cin = (unsigned char*)&inw;
    cin[0] = Sbox[cin[0]];
    cin[1] = Sbox[cin[1]];
    cin[2] = Sbox[cin[2]];
    cin[3] = Sbox[cin[3]];
    return(inw);
}

int Encrypt::RotWord(int _in)
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

void Encrypt::KeyExpansion(void* _key)
{
    /* FIPS 197  P.27 Appendix A.1 Rcon[i/Nk] */ //���� Mul���g�p����
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
