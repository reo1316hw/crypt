//参考元
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

#define NB 4
#define NBb 16                        /* 128bit 固定として規格されている(データの長さ) */

/************************************************************/
unsigned char key[32];
int w[60];                            /* FIPS 197 P.19 5.2 Key Expansion */
//int data[NB];
int nk;                               /* 4,6,8(128,192,256 bit) 鍵の長さ */
int nr;                               /* 10,12,14 ラウンド数 */

void SubBytes(char data[]);            /* FIPS 197  P.16 Figure  6 */
void ShiftRows(char data[]);           /* FIPS 197  P.17 Figure  8 */
void MixColumns(char*);               /* FIPS 197  P.18 Figure  9 */
void AddRoundKey(char*, int);          /* FIPS 197  P.19 Figure 10 */
int SubWord(int in);                  /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
int RotWord(int in);                  /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
void KeyExpansion(void*);            /* FIPS 197  P.20 Figure 11 */

int Cipher(char*);                    /* FIPS 197  P.15 Figure  5 */

using namespace std;
void cipher(char* dst);

int main()
{
    string fileName;    //ファイル名

    //ファイル名からバイナリファイルで読み込む
    cout << "暗号化するファイル名を入力してください\n";
    //キーボード入力からファイル名を取得する
    getline(cin, fileName);
    ifstream ifs(fileName, ios::binary);

    string outFileName; //ファイル名
    //ofstreamを読み取りモードで開き、末尾に移動
    std::cout << "出力するファイル名を入力してください\n";
    //キーボード入力からファイル名を取得する
    getline(cin, outFileName);
    ofstream ofs(outFileName, ios::app | ios::binary);

    ////読み込みデータ
    //char data[Block];

    //読み込みデータ
    char dataa[Block];

    //初期化ベクトル
    char initialData[Block];
    memset(initialData, 'I', Block);

    //1つ前の暗号ブロック
    char cipherBlockPre[Block];

    //暗号ブロック
    char cipherBlock[Block];

    //データ読込
    ifs.read(dataa, Block);
    //ブロック長ごとに処理
    for (int i = 0; i < Block; i++)
    {
        cipherBlock[i] = dataa[i] ^ initialData[i];
    }

    //暗号化
    cipher(cipherBlock);
    //暗号化したブロックを出力
    ofs.write(cipherBlock, Block);
    //1つ前の暗号ブロックに暗号化したブロックを格納
    memcpy(cipherBlockPre, cipherBlock, Block);
    do {
        //データ読込
        ifs.read(dataa, Block);
        //データがなかった場合終了する。
        if (ifs.eof()) break;
        //ブロック長ごとに処理
        for (int i = 0; i < Block; i++)
        {
            cipherBlock[i] = dataa[i] ^ cipherBlockPre[i];
        }

        //暗号化
        cipher(cipherBlock);
        //暗号化したブロックを出力
        ofs.write(cipherBlock, Block);
        //1つ前の暗号ブロックに暗号化したブロックを格納
        memcpy(cipherBlockPre, cipherBlock, Block);

    } while (true);

    cout << "ループ外" << endl;

    return 0;
}

void cipher(char* dst)
{
    //暗号鍵
    char cipherBlockTemp[Block];
    memset(cipherBlockTemp, 'S', Block);
    //ブロック長ごとに処理
    for (int i = 0; i < Block; i++)
    {
        //XOR暗号
        dst[i] = dst[i] ^ cipherBlockTemp[i];
    }
    return;
}

/************************************************************/
/* FIPS 197  P.16 Figure 7 */
int Sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/************************************************************/
/* FIPS 197  P.15 Figure 5 */ //暗号化
int Cipher(char data[])
{
    int i;

    AddRoundKey(data, 0);

    for (i = 1; i < nr; i++)
    {
        SubBytes(data);
        ShiftRows(data);
        MixColumns(data);
        AddRoundKey(data, i);
    }

    SubBytes(data);
    ShiftRows(data);
    AddRoundKey(data, i);
    return(i);
}

/************************************************************/
/* FIPS 197  P.16 Figure 6 */
void SubBytes(char data[])
{
    int i, j;
    unsigned char* cb = (unsigned char*)data;
    for (i = 0; i < NBb; i += 4)//理論的な意味から二重ループにしているが意味は無い
    {
        for (j = 0; j < 4; j++)
        {
            cb[i + j] = Sbox[cb[i + j]];
        }
    }
}

/************************************************************/
/* FIPS 197  P.17 Figure 8 */
void ShiftRows(char data[])
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
            cw[i4 + j + 0 * 4] = cb[i4 + j + ((j + 0) & 3) * 4];
            cw[i4 + j + 1 * 4] = cb[i4 + j + ((j + 1) & 3) * 4];
            cw[i4 + j + 2 * 4] = cb[i4 + j + ((j + 2) & 3) * 4];
            cw[i4 + j + 3 * 4] = cb[i4 + j + ((j + 3) & 3) * 4];
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
int dataget(void* data, int n)
{
    return(((unsigned char*)data)[n]);
}

/************************************************************/
/* FIPS 197  P.18 Figure 9 */
void MixColumns(char data[])
{
    int i, i4, x;
    for (i = 0; i < NB; i++)
    {
        i4 = i * 4;
        x = mul(dataget(data, i4 + 0), 2) ^
            mul(dataget(data, i4 + 1), 3) ^
            mul(dataget(data, i4 + 2), 1) ^
            mul(dataget(data, i4 + 3), 1);
        x |= (mul(dataget(data, i4 + 1), 2) ^
            mul(dataget(data, i4 + 2), 3) ^
            mul(dataget(data, i4 + 3), 1) ^
            mul(dataget(data, i4 + 0), 1)) << 8;
        x |= (mul(dataget(data, i4 + 2), 2) ^
            mul(dataget(data, i4 + 3), 3) ^
            mul(dataget(data, i4 + 0), 1) ^
            mul(dataget(data, i4 + 1), 1)) << 16;
        x |= (mul(dataget(data, i4 + 3), 2) ^
            mul(dataget(data, i4 + 0), 3) ^
            mul(dataget(data, i4 + 1), 1) ^
            mul(dataget(data, i4 + 2), 1)) << 24;
        data[i] = x;
    }
}

/************************************************************/
/* FIPS 197  P.19 Figure 10 */
void AddRoundKey(char data[], int n)
{
    int i;
    for (i = 0; i < NB; i++)
    {
        data[i] ^= w[i + NB * n];
    }
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
int SubWord(int in)
{
    int inw = in;
    unsigned char* cin = (unsigned char*)&inw;
    cin[0] = Sbox[cin[0]];
    cin[1] = Sbox[cin[1]];
    cin[2] = Sbox[cin[2]];
    cin[3] = Sbox[cin[3]];
    return(inw);
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
int RotWord(int in)
{
    int inw = in, inw2 = 0;
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
void KeyExpansion(void* key)
{
    /* FIPS 197  P.27 Appendix A.1 Rcon[i/Nk] */ //又は mulを使用する
    int Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
    int i, temp;

    memcpy(w, key, nk * 4);
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
//    int key = 12345; //任意の暗号化キー
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
//    /*printf("初期値=%d\n", str);
//    crypt = str ^ key;
//    printf("暗号化=%d\n", crypt);
//    crypt = crypt ^ key;
//    printf("複合化=%d\n", crypt);*/
//    return 0;
//}

//unsigned char cipherText;
///* 暗号化する関数 */
//unsigned char encrypt(unsigned char plainText, unsigned char key, unsigned char iv, enum cipherMode)
//{
//    // keyとivとcipherModeを使ってplainTextをぐちゃぐちゃにかき混ぜる処理をする
//    // ...
//
//    // 暗号文が出来上がる
//    return cipherText;
//}