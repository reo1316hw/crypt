#include "Encrypt.h"
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

/************************************************************/
void datadump(const char c[], void* dt, int len)
{
    int i;
    unsigned char* cdt = (unsigned char*)dt;
    printf("%s", c);
    for (i = 0; i < len * 4; i++)
    {
        printf("%02x", cdt[i]);
    }
    printf("\n");
}

Encrypt::Encrypt(int a, char* b[])
{
    //ifstream ifs(b[0]);

    //if (!ifs)
    //{
    //    cout << "Error!" << endl;
    //    return;
    //}

    //string str = "";

    //// ファイルの中身を読み取って表示
    //while (getline(ifs, str))
    //{
    //    cout << "ファイルの中身:" << str << endl;
    //}


    unsigned char keys[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                         0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };

    unsigned char init[] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                          0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };

    /* FIPS 197  P.35 Appendix C.1 AES-128 Test */
    memcpy(key, keys, 16);
    nk = 4;               //鍵の長さ 4,6,8(128,192,256 bit)
    nr = nk + 6;          //ラウンド数 10,12,14

    KeyExpansion(key);    //暗号化するための鍵の準備
    memcpy(data, init, NBb); //NBにて 4ワード 16バイトと定義している

    datadump("PLAINTEXT: ", data, 4);
    datadump("KEY:       ", key, 4);
    Encryption(data);
    datadump("暗号化:    ", data, 4);
    printf("\n");

    /* FIPS 197  P.38 Appendix C.2 AES-192 Test */
    memcpy(key, keys, 24);
    nk = 6;               //鍵の長さ 4,6,8(128,192,256 bit)
    nr = nk + 6;          //ラウンド数 10,12,14

    KeyExpansion(key);    //暗号化するための鍵の準備
    memcpy(data, init, NBb); //NBにて 4ワード 16バイトと定義している

    datadump("PLAINTEXT: ", data, 4);
    datadump("KEY:       ", key, 6);
    Encryption(data);
    datadump("暗号化:    ", data, 4);
    printf("\n");

    /* FIPS 197  P.42 Appendix C.3 AES-256 Test */
    memcpy(key, keys, 32);
    nk = 8;               //鍵の長さ 4,6,8(128,192,256 bit)
    nr = nk + 6;          //ラウンド数 10,12,14

    KeyExpansion(key);    //暗号化するための鍵の準備
    memcpy(data, init, NBb); //NBにて 4ワード 16バイトと定義している

    datadump("PLAINTEXT: ", data, 4);
    datadump("KEY:       ", key, 8);
    Encryption(data);
    datadump("暗号化:    ", data, 4);
}

/************************************************************/
/* FIPS 197  P.15 Figure 5 */ //暗号化
int Encrypt::Encryption(int data[])
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
void Encrypt::SubBytes(int data[])
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
void Encrypt::ShiftRows(int data[])
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
int Encrypt::mul(int dt, int n)
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
int Encrypt::dataget(void* data, int n)
{
    return(((unsigned char*)data)[n]);
}

/************************************************************/
/* FIPS 197  P.18 Figure 9 */
void Encrypt::MixColumns(int data[])
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
void Encrypt::AddRoundKey(int data[], int n)
{
    int i;
    for (i = 0; i < NB; i++)
    {
        data[i] ^= w[i + NB * n];
    }
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
int Encrypt::SubWord(int in)
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
int Encrypt::RotWord(int in)
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
void Encrypt::KeyExpansion(void* key)
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