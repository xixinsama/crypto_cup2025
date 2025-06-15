#include <stdio.h>

void reverseBits(unsigned char* password) {
    int i, j;
    unsigned char temp;

    for (i = 0; i < 16; i++) {
        temp = 0;
        for (j = 0; j < 8; j++) {
            temp |= ((password[i] >> j) & 1) << (7 - j);
        }
        password[i] = temp;
    }
}

void swapPositions(unsigned char* password) {
    int i;
    unsigned char temp[16];
    int positions[16] =
            {
                    13, 4, 0, 5,
                    2, 12, 11, 8,
                    10, 6, 1, 9,
                    3, 15, 7, 14
            };

    for (i = 0; i < 16; i++) {
        temp[positions[i]] = password[i];
    }

    for (i = 0; i < 16; i++) {
        password[i] = temp[i];
    }
}

void leftShiftBytes(unsigned char* password) {
    for (int i = 0; i < 16; i++) {
        password[i] = password[i] << 3 | password[i] >> 5;
    }
}



void xorWithKeys(unsigned char* password, unsigned int round) {
    int i;
    for (i = 0; i < 16; i++) {
        password[i] ^= (unsigned char)(0x78 * round & 0xFF);
    }
}

void encryptPassword(unsigned char* password) {
    int i;
    unsigned int round;

    for (round = 0; round < 16; round++) {
        reverseBits(password);
        swapPositions(password);
        leftShiftBytes(password);
        xorWithKeys(password, round);
    }
}

int main() {
    unsigned char password[17] = "1234567890";
    printf("加密前的口令为：\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", password[i]);
    }
    encryptPassword(password);
    printf("加密后的口令为：\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", password[i]);
    }
    printf("\n");
    return 0;
}