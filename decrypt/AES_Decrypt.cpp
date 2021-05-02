#include <iostream>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#define NB 4
#define NBb 16                        /* 128bit 固定として規格されている(データの長さ) */

using namespace std;

unsigned char key[32];

//読み込みデータ
char dataa[NBb];

//初期化ベクトル
char initialData[NBb];

//一時保存読み込みデータ
char dataTemp[NBb];

//1つ前の暗号ブロック
char cipherBlockPre[NBb];

int w[60];                            /* FIPS 197 P.19 5.2 Key Expansion */
//int data[NB];
int nk;                               /* 4,6,8(128,192,256 bit) 鍵の長さ */
int nr;                               /* 10,12,14 ラウンド数 */

void invShiftRows(char* data);        /* FIPS 197  P.22 Figure 13 */
void invSubBytes(char* data);         /* FIPS 197  P.22 5.3.2 */
void invMixColumns(char* data, int n); /* FIPS 197  P.23 5.3.3 */
void AddRoundKey(char* _data, int n);          /* FIPS 197  P.19 Figure 10 */
int SubWord(int in);                  /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
int RotWord(int in);                  /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
void KeyExpansion(void* key);            /* FIPS 197  P.20 Figure 11 */

int invCipher(char* _data);                 /* FIPS 197  P.21 Figure 12 */

int main(int argc, char* argv[])
{
    string fileName;    //ファイル名
    //string fileName = argv[0];    //ファイル名

    //ファイル名からバイナリファイルで読み込む
    cout << "復号するファイル名を入力してください\n";
    //キーボード入力からファイル名を取得する
    getline(cin, fileName);
    ifstream ifs(fileName, ios::binary);

    string outFileName; //ファイル名
    //string outFileName = argv[1]; //ファイル名
    //ofstreamを読み取りモードで開き、末尾に移動
    cout << "出力するファイル名を入力してください\n";
    //キーボード入力からファイル名を取得する
    getline(cin, outFileName);
    ofstream ofs(outFileName, ios::app | ios::binary);

    //復号ブロック
    char decryptBlock[NBb];

    memset(initialData, 'I', NBb);

    //データ読込
    ifs.read(dataa, NBb);

    //1つ前の暗号ブロックに暗号化されているブロックを格納
    memcpy(cipherBlockPre, dataa, NBb);

    //復号
    invCipher(dataa);

    //ブロック長ごとに処理
    for (int i = 0; i < NBb; i++)
    {
        decryptBlock[i] = dataa[i]/* ^ initialData[i]*/;
    }
    //復号したブロックを出力
    ofs.write(decryptBlock, NBb);

    do {
        //データ読込
        ifs.read(dataa, NBb);
        memcpy(dataTemp, dataa, NBb);
        //復号
        invCipher(dataa);
        //データがなかった場合終了する。
        if (ifs.eof()) break;
        //ブロック長ごとに処理
        for (int i = 0; i < NBb; i++)
        {
            decryptBlock[i] = dataa[i] ^ cipherBlockPre[i];
        }

        //復号したブロックを出力
        ofs.write(decryptBlock, NBb);

        //1つ前の暗号ブロックに暗号化されているブロックを格納
        memcpy(cipherBlockPre, dataTemp, NBb);

    } while (true);
}

/************************************************************/
/* FIPS 197  P.22 Figure 14 */
int invSbox[256] = {
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/************************************************************/
/* FIPS 197  P.21 Figure 12 */ //復号化
int invCipher(char* data)
{
    int i;

    AddRoundKey(data, nr);

    for (i = nr - 1; i > 0; i--)
    {
        invShiftRows(data);
        invSubBytes(data);
        AddRoundKey(data, i);
        invMixColumns(data, i);
    }

    invShiftRows(data);
    invSubBytes(data);
    AddRoundKey(data, 0);
    return(nr);
}

/************************************************************/
/* FIPS 197  P.22 5.3.2 */
void invSubBytes(char* data)
{
    int i, j;
    unsigned char* cb = (unsigned char*)data;
    for (i = 0; i < NBb; i += 4)//理論的な意味から二重ループにしているが意味は無い
    {
        for (j = 0; j < 4; j++)
        {
            cb[i + j] = invSbox[cb[i + j]];
        }
    }
}

/************************************************************/
/* FIPS 197  P.22 Figure 13 */
void invShiftRows(char* data)
{
    int i, j, i4;
    unsigned char* cb = (unsigned char*)data;
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


/************************************************************/
/* FIPS 197 P.10 4.2 乗算 (n倍) */
int mul(int dt, int n)
{
    int i, x = 0;
    for (i = 8; i > 0; i >>= 1)
    {
        x <<= 1;
        if (x & 0x100)
            x = (x ^ 0x1b) & 0xff;
        if ((n & i))
            x ^= dt;
    }
    return(x);
}

/************************************************************/
int dataget(void* _data, int n)
{
    return(((unsigned char*)_data)[n]);
}

/************************************************************/
/* FIPS 197  P.23 5.3.3 */
void invMixColumns(char* data, int n)
{
    int i, i4, x;
    for (i = 0; i < NB; i++)
    {
        i4 = i * 4;
        x = mul(dataget(data, i4 + 0), 14) ^
            mul(dataget(data, i4 + 1), 11) ^
            mul(dataget(data, i4 + 2), 13) ^
            mul(dataget(data, i4 + 3), 9);
        x |= (mul(dataget(data, i4 + 1), 14) ^
            mul(dataget(data, i4 + 2), 11) ^
            mul(dataget(data, i4 + 3), 13) ^
            mul(dataget(data, i4 + 0), 9)) << 8;
        x |= (mul(dataget(data, i4 + 2), 14) ^
            mul(dataget(data, i4 + 3), 11) ^
            mul(dataget(data, i4 + 0), 13) ^
            mul(dataget(data, i4 + 1), 9)) << 16;
        x |= (mul(dataget(data, i4 + 3), 14) ^
            mul(dataget(data, i4 + 0), 11) ^
            mul(dataget(data, i4 + 1), 13) ^
            mul(dataget(data, i4 + 2), 9)) << 24;
        data[i] = x;
    }
}

/************************************************************/
/* FIPS 197  P.19 Figure 10 */
void AddRoundKey(char* _data, int n)
{
    int i;
    for (i = 0; i < NB; i++)
    {
        _data[i] ^= w[i + NB * n];
    }
}