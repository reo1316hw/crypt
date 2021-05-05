#include "AES_Decrypt.h"
#include <string>
#include <iostream>
#include <fstream>

using namespace std;

#define NB 4
#define NBb 16                        /* 128bit 固定として規格されている(データの長さ) */

Decrypt::Decrypt(char* _iputFileName, char* _outputFileName)
{
    //読み込みデータ
    int data[NB];

    //初期化ベクトル
    int initialData[NB];

    //一時保存読み込みデータ
    int dataTemp[NB];

    //1つ前の暗号ブロック
    int cipherBlockPre[NB];

    //復号ブロック
    int decryptBlock[NB];

    unsigned char key[32];

    unsigned char keys[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                  0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };

    memcpy(key, keys, 16);
    nk = 4;               //鍵の長さ 4,6,8(128,192,256 bit)
    nr = nk + 6;          //ラウンド数 10,12,14

    KeyExpansion(key);    //暗号化するための鍵の準備

    //入力ファイル名
    string fileName = _iputFileName;
    //ファイル名からバイナリファイルで読み込む
    ifstream ifs(fileName, ios::binary);

    //出力ファイル名
    string outFileName = _outputFileName;
    //ofstreamを読み取りモードで開き、末尾に移動
    ofstream ofs(outFileName, ios::app | ios::binary);

    memset(initialData, 'I', NBb);

    //データ読込
    ifs.read((char*)data, NBb);

    //1つ前の暗号ブロックに暗号化されているブロックを格納
    memcpy(cipherBlockPre, data, NBb);

    //復号
    invCipher(data);

    //ブロック長ごとに処理
    for (int i = 0; i < NB; i++)
    {
        decryptBlock[i] = data[i] ^ initialData[i];
    }
    //復号したブロックを出力
    ofs.write((char*)decryptBlock, NBb);

    do {
        //データ読込
        ifs.read((char*)data, NBb);
        memcpy(dataTemp, data, NBb);
        //復号
        invCipher(data);
        //データがなかった場合終了する。
        if (ifs.eof()) break;
        //ブロック長ごとに処理
        for (int i = 0; i < NB; i++)
        {
            decryptBlock[i] = data[i] ^ cipherBlockPre[i];
        }

        //復号したブロックを出力
        ofs.write((char*)decryptBlock, NBb);

        //1つ前の暗号ブロックに暗号化されているブロックを格納
        memcpy(cipherBlockPre, dataTemp, NBb);

    } while (true);
}

//復号化
int Decrypt::invCipher(int* _data)
{
    int i;

    AddRoundKey(_data, nr);

    for (i = nr - 1; i > 0; i--)
    {
        invShiftRows(_data);
        invSubBytes(_data);
        AddRoundKey(_data, i);
        invMixColumns(_data);
    }

    invShiftRows(_data);
    invSubBytes(_data);
    AddRoundKey(_data, 0);
    return(nr);
}

void Decrypt::invSubBytes(int* _data)
{
    int i, j;
    unsigned char* cb = (unsigned char*)_data;
    for (i = 0; i < NBb; i += 4)//理論的な意味から二重ループにしているが意味は無い
    {
        for (j = 0; j < 4; j++)
        {
            cb[i + j] = invSbox[cb[i + j]];
        }
    }
}

void Decrypt::invShiftRows(int* _data)
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

int Decrypt::mul(int _dt, int _n)
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

/************************************************************/
int Decrypt::dataget(void* _data, int _n)
{
    return(((unsigned char*)_data)[_n]);
}

/************************************************************/
/* FIPS 197  P.23 5.3.3 */
void Decrypt::invMixColumns(int* _data)
{
    int i, i4, x;
    for (i = 0; i < NB; i++)
    {
        i4 = i * 4;
        x = mul(dataget(_data, i4 + 0), 14) ^
            mul(dataget(_data, i4 + 1), 11) ^
            mul(dataget(_data, i4 + 2), 13) ^
            mul(dataget(_data, i4 + 3), 9);
        x |= (mul(dataget(_data, i4 + 1), 14) ^
            mul(dataget(_data, i4 + 2), 11) ^
            mul(dataget(_data, i4 + 3), 13) ^
            mul(dataget(_data, i4 + 0), 9)) << 8;
        x |= (mul(dataget(_data, i4 + 2), 14) ^
            mul(dataget(_data, i4 + 3), 11) ^
            mul(dataget(_data, i4 + 0), 13) ^
            mul(dataget(_data, i4 + 1), 9)) << 16;
        x |= (mul(dataget(_data, i4 + 3), 14) ^
            mul(dataget(_data, i4 + 0), 11) ^
            mul(dataget(_data, i4 + 1), 13) ^
            mul(dataget(_data, i4 + 2), 9)) << 24;
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

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
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


/************************************************************/
/* FIPS 197  P.20 Figure 11 */
void Decrypt::KeyExpansion(void* _key)
{
    /* FIPS 197  P.27 Appendix A.1 Rcon[i/Nk] */ //又は mulを使用する
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