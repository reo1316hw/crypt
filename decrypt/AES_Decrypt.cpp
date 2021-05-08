#include "AES_Decrypt.h"

/**
 * @fn コンストラクタ
 * @param _inputFileName 入力ファイル名
 * @param _outputFileName 出力ファイル名
 */
Decrypt::Decrypt(char* _inputFileName, char* _outputFileName)
    : mKeyLength(8)             //鍵の長さ 4,6,8(128,192,256 bit)
    , mRound(mKeyLength + 6)    //ラウンド数 10,12,14
    , mWritingRoopFlag(true)
    , mIfs(nullptr)
    , mOfs(nullptr)
{
    //入力ファイルを開く処理
    bool practicable = OpenInputFile(_inputFileName);
    //書き込むための出力ファイルを生成
    mOfs = new ofstream(_outputFileName, ios::app | ios::binary);

    //共通鍵の長さを指定してコピー
    memcpy(mKey, mKeys, mKeyLength * 4);

    //復号するための鍵の準備
    KeyExpansion(mKey);

    //入力ファイルが開かれたら書き込み処理を行う
    if (practicable)
    {
        //初回の1ブロック分の復号データを書き込み
        InitWritingDecryptData();
        //EOFまで復号したデータを書き込み
        WritingDecryptData();
    }
    //入力ファイルが開けなかったら書き込み処理を行わない
    else
    {
        return;
    }

    practicable = false;
}

/**
 * @fn デストラクタ
 */
Decrypt::~Decrypt()
{
    delete mIfs;
    delete mOfs;
}

/**
 * @fn 入力ファイルを開く
 * @param _inputFileName 入力ファイル名
 * @return true : 開けた, false : 開けなかった
 */
bool Decrypt::OpenInputFile(char* _inputFileName)
{
    //ファイル名からバイナリファイルで読み込む
    mIfs = new ifstream(_inputFileName, ios::binary);

    //ファイルが開けたらtrueを返す
    if (mIfs)
    {
        return true;
    }
    //ファイルが開けなかったらfalseを返す
    else
    {
        cout << "ファイルが開けませんでした" << endl;
        return false;
    }
}

/**
 * @fn 初回の1ブロック分の復号データを書き込み
 */
void Decrypt::InitWritingDecryptData()
{
    //初期化ベクトルの中身を全て"R" = 0x52にする
    memset(mInitialData, 'R', NBb);

    //最初の1ブロックをデータ読込
    mIfs->read((char*)mData, NBb);

    //1つ前の暗号ブロックに暗号化されているブロックを格納
    memcpy(mEncryptBlockPre, mData, NBb);

    //最初の1ブロックを復号
    InvCipher(mData);

    //復号ブロックに読み込んだデータをnバイト分XORして代入(n = バイト数)
    for (int i = 0; i < NB; i++)
    {
        mDecryptBlock[i] = mData[i] ^ mInitialData[i];
    }

    //復号した最初の1ブロックを書き込み
    mOfs->write((char*)mDecryptBlock, NBb);
}

/**
 * @fn EOFまで復号したデータを書き込み
 */
void Decrypt::WritingDecryptData()
{
    //データがなかった場合終了する。
    while (mWritingRoopFlag)
    {
        //1ブロック分データ読込
        mIfs->read((char*)mData, NBb);

        //データがなかった場合終了する。
        if (mIfs->eof())
        {
            mWritingRoopFlag = false;
            break;
        }

        //一時保存用のブロックに暗号化されているブロックを格納
        memcpy(mDataTemp, mData, NBb);

        //1ブロック分復号
        InvCipher(mData);

        //復号ブロックに読み込んだデータをnバイト分XORして代入(n = バイト数)
        for (int i = 0; i < NB; i++)
        {
            mDecryptBlock[i] = mData[i] ^ mEncryptBlockPre[i];
        }

        //復号した1ブロックを出力
        mOfs->write((char*)mDecryptBlock, NBb);

        //1つ前の暗号ブロックに一時保存したブロックを格納
        memcpy(mEncryptBlockPre, mDataTemp, NBb);
    }
}


/**
 * @fn AESによる復号
 * @param _data 入力ファイルを読み込んだデータ
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
    for (i = 0; i < NBb; i += 4)//理論的な意味から二重ループにしているが意味は無い
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
 * @fn ラウンド鍵とのXORをとる
 * @param _data 入力ファイルを読み込んだデータ
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
 * @fn 復号するための鍵の準備
 * @param _key 共通鍵
 */
void Decrypt::KeyExpansion(void* _key)
{
    /* FIPS 197  P.27 Appendix A.1 Rcon[i/Nk] */ //又は mulを使用する
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