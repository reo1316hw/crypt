#include "AES_Encrypt.h"

/**
 * @fn �R���X�g���N�^
 * @param _inputFileName ���̓t�@�C����
 * @param _outputFileName �o�̓t�@�C����
 */
Encrypt::Encrypt(char* _inputFileName, char* _outputFileName, int _keyLength)
    : mKeyLength(_keyLength)             //���̒��� 4,6,8(128,192,256 bit)
    , mRound(mKeyLength + 6)    //���E���h�� 10,12,14
    , mWritingRoopFlag(true)
    , mIfs(nullptr)
    , mOfs(nullptr)
{
    //���̓t�@�C�����J������
    bool practicable = OpenInputFile(_inputFileName);

    string s = "a.png";

    //�������ނ��߂̏o�̓t�@�C���𐶐�
    mOfs = new ofstream(s, ios::app | ios::binary);

    //���ʌ��̒������w�肵�ăR�s�[
    memcpy(mKey, mKeys, mKeyLength * 4);

    //�Í������邽�߂̌��̏���
    KeyExpansion(mKey);

    //���̓t�@�C�����J���ꂽ�珑�����ݏ������s��
    if (practicable)
    {
        //�����1�u���b�N���̈Í����f�[�^����������
        InitWritingEncryptData();
        //EOF�܂ňÍ��������f�[�^����������
        WritingEncryptData();

        cout << "�Í�������" << endl;
    }
    //���̓t�@�C�����J���Ȃ������珑�����ݏ������s��Ȃ�
    else
    {
        cout << "�Í������s" << endl;
        return;
    }

    practicable = false;
}

/**
 * @fn �f�X�g���N�^
 */
Encrypt::~Encrypt()
{
    delete mIfs;
    delete mOfs;
}

/**
 * @fn ���̓t�@�C�����J��
 * @param _inputFileName ���̓t�@�C����
 * @return true : �J����, false : �J���Ȃ�����
 */
bool Encrypt::OpenInputFile(char* _inputFileName)
{
    string s = "heart.png";

    //�t�@�C��������o�C�i���t�@�C���œǂݍ���
    mIfs = new ifstream(s, ios::binary);

    //�t�@�C�������݂��邩�`�F�b�N
    bool fileCheck = mIfs->is_open();

    //�t�@�C�����J���Ȃ�������false��Ԃ�
    if (!fileCheck)
    {
        cout << "���̓t�@�C�����J���܂���ł���" << endl;
        return false;
    }

    //�t�@�C�����J������true��Ԃ�
    cout << "���̓t�@�C�����J���܂���" << endl;
    return true;
}

/**
 * @fn �����1�u���b�N���̈Í����f�[�^����������
 */
void Encrypt::InitWritingEncryptData()
{
    //�������x�N�g���̒��g��S��"R" = 0x52�ɂ���
    memset(mInitialData, 'R', NBb);

    //�ŏ���1�u���b�N���f�[�^�Ǎ�
    mIfs->read((char*)mData, NBb);

    //�Í��u���b�N�ɓǂݍ��񂾃f�[�^��n�o�C�g��XOR���đ��(n = �o�C�g��)
    for (int i = 0; i < NB; i++)
    {
        mEncryptBlock[i] = mData[i] ^ mInitialData[i];
    }

    //�ŏ���1�u���b�N���Í���
    Cipher(mEncryptBlock);

    //�Í��������ŏ���1�u���b�N����������
    mOfs->write((char*)mEncryptBlock, NBb);

    //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
    memcpy(mEncryptBlockPre, mEncryptBlock, NBb);
}

/**
 * @fn EOF�܂ňÍ��������f�[�^����������
 */
void Encrypt::WritingEncryptData()
{
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

        //�u���b�N�����Ƃɏ���
        //�Í��u���b�N�ɓǂݍ��񂾃f�[�^��n�o�C�g��XOR���đ��(n = �o�C�g��)
        for (int i = 0; i < NB; i++)
        {
            mEncryptBlock[i] = mData[i] ^ mEncryptBlockPre[i];
        }

        //1�u���b�N���Í���
        Cipher(mEncryptBlock);

        //�Í�������1�u���b�N����������
        mOfs->write((char*)mEncryptBlock, NBb);

        //1�O�̈Í��u���b�N�ɈÍ�������Ă���u���b�N���i�[
        memcpy(mEncryptBlockPre, mEncryptBlock, NBb);
    }
}

/**
 * @fn AES�ɂ��Í���
 * @param _data ���̓t�@�C����ǂݍ��񂾃f�[�^
 */
int Encrypt::Cipher(int* _data)
{
    int i;

    AddRoundKey(_data, 0);

    for (i = 1; i < mRound; i++)
    {
        SubBytes(_data);
        ShiftRows(_data);
        MixColumns(_data);
        AddRoundKey(_data, i);
    }

    SubBytes(_data);
    ShiftRows(_data);
    AddRoundKey(_data, i);

    return i;
}

/**
 * @fn �e�}�X�ɕ�����ꂽ1byte���̃}�X�̓����Ŋ����\(�t�H���[�hS�{�b�N�X)��p����bit�u�����s��
 * @param _data ���̓t�@�C����ǂݍ��񂾃f�[�^
 */
void Encrypt::SubBytes(int* _data)
{
    int i, j;
    unsigned char* cb = (unsigned char*)_data;

    for (i = 0; i < NBb; i += 4)
    {
        for (j = 0; j < 4; j++)
        {
            cb[i + j] = mSbox[cb[i + j]];
        }
    }
}

/**
 * @fn 4�o�C�g�P�ʂ̍s�����K���ō��V�t�g����
 * @brief 4�~4�}�X��1�s�ڂ͍��V�t�g�����A2�s�ڂ�1���V�t�g�A3�s�ڂ�2���V�t�g�A4�s�ڂ�3���V�t�g����
 * @param _data ���̓t�@�C����ǂݍ��񂾃f�[�^
 */
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

/**
 * @fn �|���Z
 * @param _dt 1�o�C�g�̃o�C�i���f�[�^
 * @param _n �|���Z����Ώۂ̔z��̓Y����
 */
int Encrypt::Mul(int _dt, int _n)
{
    int i, x = 0;

    for (i = 8; i > 0; i >>= 1)
    {
        x <<= 1;

        if (x & 0x100)
        {
            x = (x ^ 0x1b) & 0xff;
        }  
        if (_n & i)
        {
            x ^= _dt;
        }
    }

    return x;
}

/**
 * @fn unsigned char�^�ɕϊ�
 * @param _data ���̓t�@�C����ǂݍ��񂾃f�[�^
 * @param _n ���̓t�@�C���̃f�[�^�z��̓Y����
 */
int Encrypt::Dataget(void* _data, int _n)
{
    return ((unsigned char*)_data)[_n];
}

/**
 * @fn �r�b�g���Z�ɂ��S�o�C�g�P�ʂ̍s��ϊ�
 * @param _data ���̓t�@�C����ǂݍ��񂾃f�[�^
 */
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

/**
 * @fn ���E���h���Ƃ�XOR���Ƃ�
 * @param _data ���̓t�@�C����ǂݍ��񂾃f�[�^
 * @param _roundCount ���E���h��
 */
void Encrypt::AddRoundKey(int* _data, int _roundCount)
{
    int i;

    for (i = 0; i < NB; i++)
    {
        _data[i] ^= mRoundKey[i + NB * _roundCount];
    }
}

/**
 * @fn Sbox�ɂ��byte�P�ʂ̒u��
 * @param _in ��]�����������ʌ�
 */
int Encrypt::SubWord(int _in)
{
    int inw = _in;
    unsigned char* cin = (unsigned char*)&inw;

    cin[0] = mSbox[cin[0]];
    cin[1] = mSbox[cin[1]];
    cin[2] = mSbox[cin[2]];
    cin[3] = mSbox[cin[3]];

    return inw;
}

/**
 * @fn 1word��byte�P�ʂō��ɉ�]����
 * @param _in ���ʌ���n�Ԗ�
 */
int Encrypt::RotWord(int _in)
{
    int inw = _in, inw2 = 0;
    unsigned char* cin = (unsigned char*)&inw;
    unsigned char* cin2 = (unsigned char*)&inw2;

    cin2[0] = cin[1];
    cin2[1] = cin[2];
    cin2[2] = cin[3];
    cin2[3] = cin[0];

    return inw2;
}

/**
 * @fn �Í������邽�߂̌��̏���
 * @param _key ���ʌ�
 */
void Encrypt::KeyExpansion(void* _key)
{
    int Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
    int i, temp;

    memcpy(mRoundKey, _key, mKeyLength * 4);

    for (i = mKeyLength; i < NB * (mRound + 1); i++)
    {
        temp = mRoundKey[i - 1];

        if ((i % mKeyLength) == 0)
        {
            temp = SubWord(RotWord(temp)) ^ Rcon[(i / mKeyLength) - 1];
        }
        else if (mKeyLength > 6 && (i % mKeyLength) == 4)
        {
            temp = SubWord(temp);
        }
            
        mRoundKey[i] = mRoundKey[i - mKeyLength] ^ temp;
    }
}
