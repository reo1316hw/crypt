#include "AES_Decrypt.h"

/**
 * @fn �R���X�g���N�^
 * @param _inputFileName ���̓t�@�C����
 * @param _outputFileName �o�̓t�@�C����
 */
Decrypt::Decrypt(char* _inputFileName, char* _outputFileName)
    : mWritingRoopFlag(true)
{
    //���̓t�@�C�����J������
    bool practicable = OpenInputFile(_inputFileName);
    //�������ނ��߂̏o�̓t�@�C���𐶐�
    mOfs = new ofstream(_outputFileName, ios::app | ios::binary);

    memcpy(mKey, mKeys, 16);
    mKeyLength = 4;               //���̒��� 4,6,8(128,192,256 bit)
    mRound = mKeyLength + 6;      //���E���h�� 10,12,14

    //�������邽�߂̌��̏���
    KeyExpansion(mKey);

    //���̓t�@�C�����J���ꂽ�珑�����ݏ������s��
    if (practicable)
    {
        //�����1�u���b�N���̕����f�[�^����������
        InitWritingDecryptData();
        //EOF�܂ŕ��������f�[�^����������
        WritingDecryptData();
    }
    //���̓t�@�C�����J���Ȃ������珑�����ݏ������s��Ȃ�
    else
    {
        return;
    }

    practicable = false;
}

/**
 * @fn �f�X�g���N�^
 */
Decrypt::~Decrypt()
{
    delete mIfs;
    delete mOfs;
}

/**
 * @fn ���̓t�@�C�����J��
 * @param _inputFileName ���̓t�@�C����
 * @return true : �J����, false : �J���Ȃ�����
 */
bool Decrypt::OpenInputFile(char* _inputFileName)
{
    //�t�@�C��������o�C�i���t�@�C���œǂݍ���
    mIfs = new ifstream(_inputFileName, ios::binary);

    //�t�@�C�����J������true��Ԃ�
    if (mIfs)
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

/**
 * @fn �����1�u���b�N���̕����f�[�^����������
 */
void Decrypt::InitWritingDecryptData()
{
    //�������x�N�g���̒��g��S��"I" = 0x49�ɂ���
    memset(mInitialData, 'I', NBb);

    //�ŏ���1�u���b�N���f�[�^�Ǎ�
    mIfs->read((char*)mData, NBb);

    //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
    memcpy(mEncryptBlockPre, mData, NBb);

    //�ŏ���1�u���b�N�𕜍�
    InvCipher(mData);

    //�����u���b�N�ɓǂݍ��񂾃f�[�^��n�o�C�g��XOR���đ��(n = �o�C�g��)
    for (int i = 0; i < NB; i++)
    {
        mDecryptBlock[i] = mData[i] ^ mInitialData[i];
    }

    //���������ŏ���1�u���b�N����������
    mOfs->write((char*)mDecryptBlock, NBb);
}

/**
 * @fn EOF�܂ŕ��������f�[�^����������
 */
void Decrypt::WritingDecryptData()
{
    //�f�[�^���Ȃ������ꍇ�I������B
    while (mWritingRoopFlag)
    {
        //1�u���b�N���f�[�^�Ǎ�
        mIfs->read((char*)mData, NBb);

        //�f�[�^���Ȃ������ꍇ�I������B
        if (mIfs->eof())
        {
            mWritingRoopFlag = false;
            break;
        }

        //�ꎞ�ۑ��p�̃u���b�N�ɈÍ�������Ă���u���b�N���i�[
        memcpy(mDataTemp, mData, NBb);

        //1�u���b�N������
        InvCipher(mData);

        //�����u���b�N�ɓǂݍ��񂾃f�[�^��n�o�C�g��XOR���đ��(n = �o�C�g��)
        for (int i = 0; i < NB; i++)
        {
            mDecryptBlock[i] = mData[i] ^ mEncryptBlockPre[i];
        }

        //��������1�u���b�N���o��
        mOfs->write((char*)mDecryptBlock, NBb);

        //1�O�̈Í��u���b�N�Ɉꎞ�ۑ������u���b�N���i�[
        memcpy(mEncryptBlockPre, mDataTemp, NBb);
    }
}


/**
 * @fn AES�ɂ�镜��
 * @param _data ���̓t�@�C����ǂݍ��񂾃f�[�^
 */
int Decrypt::InvCipher(int* _data)
{
    int i;

    AddRoundKey(_data, mRound);

    for (i = mRound - 1; i > 0; i--)
    {
        InvShiftRows(_data);
        InvSubBytes(_data);
        AddRoundKey(_data, i);
        InvMixColumns(_data);
    }

    InvShiftRows(_data);
    InvSubBytes(_data);
    AddRoundKey(_data, 0);
    return(mRound);
}

void Decrypt::InvSubBytes(int* _data)
{
    int i, j;
    unsigned char* cb = (unsigned char*)_data;
    for (i = 0; i < NBb; i += 4)//���_�I�ȈӖ������d���[�v�ɂ��Ă��邪�Ӗ��͖���
    {
        for (j = 0; j < 4; j++)
        {
            cb[i + j] = mInvSbox[cb[i + j]];
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

/**
 * @fn ���E���h���Ƃ�XOR���Ƃ�
 * @param _data ���̓t�@�C����ǂݍ��񂾃f�[�^
 */
void Decrypt::AddRoundKey(int* _data, int _n)
{
    int i;
    for (i = 0; i < NB; i++)
    {
        _data[i] ^= mRoundKey[i + NB * _n];
    }
}

int Decrypt::SubWord(int _in)
{
    int inw = _in;
    unsigned char* cin = (unsigned char*)&inw;
    cin[0] = mSbox[cin[0]];
    cin[1] = mSbox[cin[1]];
    cin[2] = mSbox[cin[2]];
    cin[3] = mSbox[cin[3]];
    return(inw);
}

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

/**
 * @fn �������邽�߂̌��̏���
 * @param _key ���ʌ�
 */
void Decrypt::KeyExpansion(void* _key)
{
    /* FIPS 197  P.27 Appendix A.1 Rcon[i/Nk] */ //���� mul���g�p����
    int Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
    int i, temp;

    memcpy(mRoundKey, _key, mKeyLength * 4);
    for (i = mKeyLength; i < NB * (mRound + 1); i++)
    {
        temp = mRoundKey[i - 1];
        if ((i % mKeyLength) == 0)
            temp = SubWord(RotWord(temp)) ^ Rcon[(i / mKeyLength) - 1];
        else if (mKeyLength > 6 && (i % mKeyLength) == 4)
            temp = SubWord(temp);
        mRoundKey[i] = mRoundKey[i - mKeyLength] ^ temp;
    }
}