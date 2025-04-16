#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


// Caesar and August (key = 1)
void caesarEncrypt(char *plaintext, char *ciphertext, int shift) {
    for (int i = 0; plaintext[i]; i++) {
        if (isalpha(plaintext[i])) {
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (plaintext[i] - base + shift + 26) % 26 + base;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}

// Atbash
void atbashEncrypt(char *plaintext, char *ciphertext) {
    for (int i = 0; plaintext[i]; i++) {
        if (isalpha(plaintext[i])) {
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = base + (25 - (plaintext[i] - base));
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}

// Affine
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++)
        if ((a * x) % m == 1)
            return x;
    return -1;
}

void affineEncrypt(char *plaintext, char *ciphertext, int a, int b) {
    for (int i = 0; plaintext[i]; i++) {
        if (isalpha(plaintext[i])) {
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = ((a * (plaintext[i] - base) + b) % 26) + base;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}

void affineDecrypt(char *ciphertext, char *plaintext, int a, int b) {
    int a_inv = modInverse(a, 26);
    for (int i = 0; ciphertext[i]; i++) {
        if (isalpha(ciphertext[i])) {
            char base = isupper(ciphertext[i]) ? 'A' : 'a';
            plaintext[i] = (a_inv * ((ciphertext[i] - base - b + 26)) % 26) + base;
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[strlen(ciphertext)] = '\0';
}
//hill climb

void getKeyMatrix(int keyMatrix[2][2], char key[]) {
    for (int i = 0, k = 0; i < 2; i++)
        for (int j = 0; j < 2; j++, k++)
            keyMatrix[i][j] = (toupper(key[k]) - 'A') % 26;
}

void getMessageVector(int messageVector[2], char block[]) {
    for (int i = 0; i < 2; i++)
        messageVector[i] = (toupper(block[i]) - 'A') % 26;
}

void multiplyMatrix(int keyMatrix[2][2], int messageVector[2], int resultVector[2]) {
    for (int i = 0; i < 2; i++) {
        resultVector[i] = 0;
        for (int j = 0; j < 2; j++)
            resultVector[i] += keyMatrix[i][j] * messageVector[j];
        resultVector[i] %= 26;
    }
}

int getDeterminant(int keyMatrix[2][2]) {
    return (keyMatrix[0][0] * keyMatrix[1][1] - keyMatrix[0][1] * keyMatrix[1][0]) % 26;
}

void getInverseKeyMatrix(int keyMatrix[2][2], int invMatrix[2][2]) {
    int det = getDeterminant(keyMatrix);
    det = (det + 26) % 26;
    int detInv = modInverse(det, 26);

    invMatrix[0][0] =  keyMatrix[1][1] * detInv % 26;
    invMatrix[1][1] =  keyMatrix[0][0] * detInv % 26;
    invMatrix[0][1] = -keyMatrix[0][1] * detInv % 26;
    invMatrix[1][0] = -keyMatrix[1][0] * detInv % 26;

    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 2; j++) {
            invMatrix[i][j] = (invMatrix[i][j] + 26) % 26;
        }
}

void hillEncrypt(char *plaintext, char *ciphertext, char *key) {
    int keyMatrix[2][2], messageVector[2], cipherVector[2];
    getKeyMatrix(keyMatrix, key);

    int len = strlen(plaintext);
    if (len % 2 != 0) strcat(plaintext, "X");

    int idx = 0;
    for (int i = 0; i < strlen(plaintext); i += 2) {
        getMessageVector(messageVector, &plaintext[i]);
        multiplyMatrix(keyMatrix, messageVector, cipherVector);
        ciphertext[idx++] = cipherVector[0] + 'A';
        ciphertext[idx++] = cipherVector[1] + 'A';
    }
    ciphertext[idx] = '\0';
}

void hillDecrypt(char *ciphertext, char *plaintext, char *key) {
    int keyMatrix[2][2], invMatrix[2][2], messageVector[2], plainVector[2];
    getKeyMatrix(keyMatrix, key);
    getInverseKeyMatrix(keyMatrix, invMatrix);

    int idx = 0;
    for (int i = 0; i < strlen(ciphertext); i += 2) {
        getMessageVector(messageVector, &ciphertext[i]);
        multiplyMatrix(invMatrix, messageVector, plainVector);
        plaintext[idx++] = plainVector[0] + 'A';
        plaintext[idx++] = plainVector[1] + 'A';
    }
    plaintext[idx] = '\0';
}


// Vigenère
void vigenereEncrypt(char *plaintext, char *ciphertext, char *key, int decryptMode) {
    int keyIndex = 0, keyLength = strlen(key);
    for (int i = 0; plaintext[i]; i++) {
        if (isalpha(plaintext[i])) {
            int shift = tolower(key[keyIndex % keyLength]) - 'a';
            if (decryptMode) shift = 26 - shift;
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (plaintext[i] - base + shift) % 26 + base;
            keyIndex++;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}

// Gronsfeld
void gronsfeldEncrypt(char *plaintext, char *ciphertext, char *key, int decryptMode) {
    int keyIndex = 0, keyLength = strlen(key);
    for (int i = 0; plaintext[i]; i++) {
        if (isalpha(plaintext[i])) {
            int shift = key[keyIndex % keyLength] - '0';
            if (decryptMode) shift = 26 - shift;
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (plaintext[i] - base + shift) % 26 + base;
            keyIndex++;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}

// Beaufort
void beaufortEncrypt(char *plaintext, char *ciphertext, char *key) {
    int keyLength = strlen(key);
    for (int i = 0, keyIndex = 0; plaintext[i]; i++) {
        if (isalpha(plaintext[i])) {
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            int keyVal = tolower(key[keyIndex % keyLength]) - 'a';
            ciphertext[i] = (26 + keyVal - (tolower(plaintext[i]) - 'a')) % 26 + base;
            keyIndex++;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}

// Autoclave
void autoclaveEncrypt(char *plaintext, char *ciphertext, char *key, int decryptMode) {
    char fullKey[1024];
    strcpy(fullKey, key);
    if (!decryptMode) strncat(fullKey, plaintext, strlen(plaintext) - strlen(key));
    for (int i = 0; plaintext[i]; i++) {
        if (isalpha(plaintext[i])) {
            int shift = tolower(fullKey[i]) - 'a';
            if (decryptMode) shift = 26 - shift;
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (plaintext[i] - base + shift) % 26 + base;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}

// NGram
void ngramEncrypt(char *plaintext, char *ciphertext) {
    char *ngrams[][2] = {
        {"TH", "XA"}, {"HE", "XB"}, {"IN", "XC"}, {"ER", "XD"}, {"AN", "XE"},
        {"RE", "XF"}, {"ND", "XG"}, {"ON", "XH"}, {"EN", "XI"}, {"AT", "XJ"}
    };
    char paddedText[1024];
    strncpy(paddedText, plaintext, sizeof(paddedText));
    if (strlen(paddedText) % 2 != 0) strcat(paddedText, "X");

    int outputIndex = 0;
    for (int i = 0; i < strlen(paddedText); i += 2) {
        char pair[3] = {toupper(paddedText[i]), toupper(paddedText[i + 1]), '\0'};
        int replaced = 0;
        for (int j = 0; j < 10; j++) {
            if (strcmp(pair, ngrams[j][0]) == 0) {
                ciphertext[outputIndex++] = ngrams[j][1][0];
                ciphertext[outputIndex++] = ngrams[j][1][1];
                replaced = 1;
                break;
            }
        }
        if (!replaced) {
            ciphertext[outputIndex++] = pair[0];
            ciphertext[outputIndex++] = pair[1];
        }
    }
    ciphertext[outputIndex] = '\0';
}

// Rail Fence
void railFenceEncrypt(char *plaintext, char *ciphertext, int numRails) {
    int len = strlen(plaintext);
    char rail[numRails][len];
    for (int i = 0; i < numRails; i++)
        for (int j = 0; j < len; j++)
            rail[i][j] = '\n';

    int row = 0, dirDown = 0;
    for (int i = 0; i < len; i++) {
        rail[row][i] = plaintext[i];
        if (row == 0 || row == numRails - 1)
            dirDown = !dirDown;
        row += dirDown ? 1 : -1;
    }

    int idx = 0;
    for (int i = 0; i < numRails; i++)
        for (int j = 0; j < len; j++)
            if (rail[i][j] != '\n')
                ciphertext[idx++] = rail[i][j];
    ciphertext[idx] = '\0';
}

// Route Cipher
void routeEncrypt(char *plaintext, char *ciphertext, int numRows, int numCols) {
    char grid[numRows][numCols];
    int k = 0;
    for (int i = 0; i < numRows && k < strlen(plaintext); i++)
        for (int j = 0; j < numCols && k < strlen(plaintext); j++)
            grid[i][j] = plaintext[k++];

    int index = 0, top = 0, bottom = numRows - 1, left = 0, right = numCols - 1;
    while (top <= bottom && left <= right) {
        for (int i = left; i <= right; i++) ciphertext[index++] = grid[top][i];
        top++;
        for (int i = top; i <= bottom; i++) ciphertext[index++] = grid[i][right];
        right--;
        for (int i = right; i >= left; i--) ciphertext[index++] = grid[bottom][i];
        bottom--;
        for (int i = bottom; i >= top; i--) ciphertext[index++] = grid[i][left];
        left++;
    }
    ciphertext[index] = '\0';
}

// Myszkowski
void myszkowskiEncrypt(char *plaintext, char *ciphertext, char *key) {
    int len = strlen(plaintext), keyLen = strlen(key), numRows = (len + keyLen - 1) / keyLen;
    char matrix[numRows][keyLen];
    memset(matrix, 'X', sizeof(matrix));
    for (int i = 0, idx = 0; i < numRows && idx < len; i++)
        for (int j = 0; j < keyLen && idx < len; j++)
            matrix[i][j] = plaintext[idx++];

    int idx = 0;
    for (char ch = '1'; ch <= '9'; ch++) {
        for (int col = 0; col < keyLen; col++) {
            if (key[col] == ch) {
                for (int row = 0; row < numRows; row++)
                    ciphertext[idx++] = matrix[row][col];
            }
        }
    }
    ciphertext[idx] = '\0';
}

// Main
int main() {
    int cipherChoice, mode;
    char plaintext[1024], ciphertext[1024], key[1024];
    int shift, a, b, rails, rows, cols;

    printf("Select Mode:\n1. Encrypt\n2. Decrypt\nChoice: ");
    scanf("%d", &mode);
    getchar();

    printf("\nSelect Cipher:\n");
    printf("1. Caesar\n2. Atbash\n3. August\n4. Affine\n5. Vigenère\n6. Gronsfeld\n");
    printf("7. Beaufort\n8. Autoclave\n9. NGram\n10. Hill climb\n");
    printf("11. Rail Fence\n12. Route\n13. Myszkowski\nChoice: ");
    scanf("%d", &cipherChoice);
    getchar();

    printf("\nEnter text: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = 0;

    switch (cipherChoice) {
        case 1:
            printf("Enter shift value: ");
            scanf("%d", &shift);
            caesarEncrypt(plaintext, ciphertext, mode == 1 ? shift : -shift);
            break;
        case 2:
            atbashEncrypt(plaintext, ciphertext);
            break;
        case 3:
            caesarEncrypt(plaintext, ciphertext, mode == 1 ? 1 : -1);
            break;
        case 4:
            printf("Enter 'a' and 'b': ");
            scanf("%d%d", &a, &b);
            if (mode == 1)
                affineEncrypt(plaintext, ciphertext, a, b);
            else
                affineDecrypt(plaintext, ciphertext, a, b);
            break;
        case 5:
            printf("Enter key: ");
            scanf("%1023s", key);
            vigenereEncrypt(plaintext, ciphertext, key, mode == 2);
            break;
        case 6:
            printf("Enter numeric key: ");
            scanf("%1023s", key);
            gronsfeldEncrypt(plaintext, ciphertext, key, mode == 2);
            break;
        case 7:
            printf("Enter key: ");
            scanf("%1023s", key);
            beaufortEncrypt(plaintext, ciphertext, key);
            break;
        case 8:
            printf("Enter key: ");
            scanf("%1023s", key);
            autoclaveEncrypt(plaintext, ciphertext, key, mode == 2);
            break;
        case 9:
            if (mode == 2) {
                printf("Decryption not supported for NGram.\n");
                return 1;
            }
            ngramEncrypt(plaintext, ciphertext);
            break;
        case 10: {
            printf("Enter 4-letter key (e.g., GYBN): ");
            scanf("%s", key);
            if (strlen(key) != 4) {
                printf("Key must be 4 letters.\n");
                return 1;
            }
            for (int i = 0; i < 4; i++) {
                if (!isalpha(key[i])) {
                    printf("Key must only contain letters.\n");
                    return 1;
                }
            }
            for (int i = 0; i < strlen(plaintext); i++)
                plaintext[i] = toupper(plaintext[i]);

            if (mode == 1)
                hillEncrypt(plaintext, ciphertext, key);
            else
                hillDecrypt(plaintext, ciphertext, key);
            break;
        }
        case 11:
            printf("Enter number of rails: ");
            scanf("%d", &rails);
            if (mode == 1)
                railFenceEncrypt(plaintext, ciphertext, rails);
            else {
                printf("Decryption not implemented for Rail Fence.\n");
                return 1;
            }
            break;
        case 12:
            printf("Enter number of rows and columns: ");
            scanf("%d%d", &rows, &cols);
            if (mode == 1)
                routeEncrypt(plaintext, ciphertext, rows, cols);
            else {
                printf("Decryption not implemented for Route.\n");
                return 1;
            }
            break;
        case 13:
            printf("Enter numeric key: ");
            scanf("%1023s", key);
            if (mode == 1)
                myszkowskiEncrypt(plaintext, ciphertext, key);
            else {
                printf("Decryption not implemented for Myszkowski.\n");
                return 1;
            }
            break;
        default:
            printf("Invalid choice.\n");
            return 1;
    }

    printf("\nResult: %s\n", ciphertext);
    return 0;
}
