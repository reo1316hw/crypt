#include "AES_Encrypt.h"

/**
 * @fn �R�}���h���C�������̃G���[�`�F�b�N
 * @param argc �����̌�
 * @param argv[] ����������̔z��ւ̃|�C���^
 * @return true:�G���[�Ȃ�(����),false:�G���[
 */
bool ErrorHandling(int argc, char* argv[])
{
    string commandLine1 = "-i";
    string commandLine3 = "-o";

    //if (argc <= 1)
    //{
    //    cout << "�R�}���h���C������������܂���" << endl;
    //    return false;
    //}

    //if (argc >= 6)
    //{
    //    cout << "�R�}���h���C���������������܂�" << endl;
    //    return false;
    //}

    //if (argv[1] != commandLine1)
    //{
    //    cout << "1�Ԗڂ̃R�}���h���C��������'-i'�Ŏw�肵�Ă�������" << endl;
    //    return false;
    //}

    //if (argv[3] != commandLine3)
    //{
    //    cout << "3�Ԗڂ̃R�}���h���C��������'-o'�Ŏw�肵�Ă�������" << endl;
    //    return false;
    //}

    return true;
}

int main(int argc, char* argv[])
{
    //�R�}���h���C�������̃G���[�`�F�b�N
    if (!ErrorHandling(argc, argv))
    {
        return 0;
    }

    //���ʌ��̒���
    int keyLength;

    while (true)
    {
        cout << "-------------------------------------------------------------------" << endl;
        cout << "���ʌ��̒������w�肵�Ă�������(4�A6�A8�̂����ꂩ����͂��Ă�������)" << endl;

        //���ʌ��̒��������
        cin >> keyLength;

        //���͂��ꂽ���l��4,6,8��������CBC���[�h��AES�Í����������s��
        if (keyLength == 4 || keyLength == 6 || keyLength == 8)
        {
            //CBC���[�h��AES�Í���
            Encrypt encrypt(argv[2], argv[4], keyLength);

            break;
        }
        else
        {
            cout << "���͂������l�Ɍ�肪����܂�" << endl;
        }

        cout << endl;
    }

    return 0;
}