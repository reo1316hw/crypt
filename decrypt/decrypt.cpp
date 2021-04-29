#include "Decrypt.h"
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

//参考元　https://web.archive.org/web/20090503235219/http://www-ailab.elcom.nitech.ac.jp/security/aes/overview.html

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

Decrypt::Decrypt(char* _OutputFileName[])
{
    //ifstream ifs(*_OutputFileName);

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

    /* FIPS 197  P.35 Appendix C.1 AES-128 Test */
    nk = 4;               //鍵の長さ 4,6,8(128,192,256 bit)
    nr = nk + 6;          //ラウンド数 10,12,14

    Decryption(data);
    cout << data << endl;

    /* FIPS 197  P.38 Appendix C.2 AES-192 Test */
    nk = 6;               //鍵の長さ 4,6,8(128,192,256 bit)
    nr = nk + 6;          //ラウンド数 10,12,14

    Decryption(data);
    cout << data << endl;

    /* FIPS 197  P.42 Appendix C.3 AES-256 Test */
    nk = 8;               //鍵の長さ 4,6,8(128,192,256 bit)
    nr = nk + 6;          //ラウンド数 10,12,14

    Decryption(data);
    cout << data << endl;
}

/************************************************************/
/* FIPS 197  P.21 Figure 12 */ //復号化
int Decrypt::Decryption(int data[])
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
void Decrypt::invSubBytes(int data[])
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
void Decrypt::invShiftRows(int data[])
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
/* FIPS 197  P.23 5.3.3 */
void Decrypt::invMixColumns(int data[], int n)
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
/* FIPS 197 P.10 4.2 乗算 (n倍) */
int Decrypt::mul(int dt, int n)
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
int Decrypt::dataget(void* data, int n)
{
    return(((unsigned char*)data)[n]);
}

/************************************************************/
/* FIPS 197  P.19 Figure 10 */
void Decrypt::AddRoundKey(int data[], int n)
{
    int i;
    for (i = 0; i < NB; i++)
    {
        data[i] ^= w[i + NB * n];
    }
}