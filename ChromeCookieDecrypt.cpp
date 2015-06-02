//
//  ChromeCookieDecrypt.cpp
//  synccore
//
//  Created by yuyg on 15/6/2.
//  Copyright (c) 2015年 emacle. All rights reserved.
//

#include "ChromeCookieDecrypt.h"
#include "sqlite3.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>

const char kSalt[] = "saltysalt";
const int kDerivedKeySizeInBits = 128;
const int kEncryptionIterations = 1003;
const char kEncryptionVersionPrefix[] = "v10";

bool deriveKeyFromPassword(const char *, int, const unsigned char *, int, unsigned char *);
int decrypt(const unsigned char *, int, const unsigned char *, const unsigned char *, unsigned char*);

int readOneCookieForTest(sqlite3 *db, string *name, string *value)
{
    const char *zSql = "select name, encrypted_value from cookies order by last_access_utc desc limit 1";
    sqlite3_stmt *pStmt;
    int rc;
    
    do
    {
        rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
        if( rc!=SQLITE_OK )
        {
            return rc;
        }
        /* Bind the key to the SQL variable. */
        //sqlite3_bind_text(pStmt, 1, zKey, -1, SQLITE_STATIC);
        
        rc = sqlite3_step(pStmt);
        if( rc==SQLITE_ROW )
        {
            int name_len = sqlite3_column_bytes(pStmt, 0);
            int blob_len = sqlite3_column_bytes(pStmt, 1);
            *name = string((const char*)sqlite3_column_text(pStmt, 0), name_len);
            *value = string((const char*)sqlite3_column_blob(pStmt, 1), blob_len);
            //*pzBlob = (unsigned char *)malloc(*pnBlob);
            //memcpy(*pzBlob, sqlite3_column_blob(pStmt, 0), *pnBlob);
        }
        rc = sqlite3_finalize(pStmt);
    } while( rc==SQLITE_SCHEMA );
    
    return rc;
}

void databaseError(sqlite3* db)
{
    int errcode = sqlite3_errcode(db);
    const char *errmsg = sqlite3_errmsg(db);
    fprintf(stderr, "Database error %d: %s\n", errcode, errmsg);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: decryptor chrome_master_key\n");
        return 1;
    }
    /* A 256 bit key */
    std::string password = argv[1];   //security find-generic-password -ga "Chrome"
    
    sqlite3 *db;
    //read default chrome cookie file
    int rc = sqlite3_open("/Users/yuyg/Library/Application Support/Google/Chrome/Default/Cookies", &db);
    if (rc == SQLITE_OK)
    {
        string name, enc_value;
        if( SQLITE_OK != readOneCookieForTest(db, &name, &enc_value) )
        {
            databaseError(db);
            sqlite3_close(db);
            return 1;
        }
        printf("get cookie: name, %s; value, %s\n", name.c_str(), enc_value.c_str());
        string cookie_value;
        if (!DecryptChromeCookie(password, enc_value, &cookie_value))
        {
            printf("decrypt failed: %s\n", enc_value.c_str());
            sqlite3_close(db);
            return 1;
        }
        printf("decrypt success, cookie value: %s\n", cookie_value.c_str());
    }
    else
    {
        printf("open db file failed, you should change right the cookies file path on your mac\n");
        databaseError(db);
        return 1;
    }
    sqlite3_close(db);
    return 0;
}


bool DecryptChromeCookie(const string& password, const string &enc_value, string *dec_value)
{
    if (enc_value.find(kEncryptionVersionPrefix) != 0){
        printf("invalid encrypted data\n");
        return false;
    }
    
    string raw_enc_value = enc_value.substr(strlen(kEncryptionVersionPrefix));
    
    /* A 128 bit IV */
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    memset(iv, ' ', AES_BLOCK_SIZE);
    
    /* Buffer for the decrypted text */
    unsigned char *decryptedtext = new unsigned char[raw_enc_value.size()];
    int decryptedtext_len = 0;
    bool ret = false;
    
    /* Decrypt the ciphertext */
    unsigned char aes_key[kDerivedKeySizeInBits/8] = {0};
    if (deriveKeyFromPassword(password.c_str(), password.size(), (unsigned char *)kSalt, (int)strlen(kSalt), aes_key))
    {
        decryptedtext_len = decrypt((const unsigned char *)raw_enc_value.c_str(), raw_enc_value.size(), aes_key, iv, decryptedtext);
        if (decryptedtext_len > 0)
        {
            decryptedtext[decryptedtext_len] = '\0';
            *dec_value = string((char *)decryptedtext, decryptedtext_len);
            ret = true;
        }
    }
    
    /* Clean up */
    delete[] decryptedtext;
    
    return ret;
}

bool deriveKeyFromPassword(const char *password,
                          int pass_len,
                          const unsigned char *salt,
                          int salt_len,
                          unsigned char *out)
{
    if( PKCS5_PBKDF2_HMAC_SHA1(password, pass_len, salt, salt_len, kEncryptionIterations, kDerivedKeySizeInBits/8, out) != 0 )
    {
        printf("get derived key success\n");
        return true;
    }
    else
    {
        printf("PKCS5_PBKDF2_HMAC_SHA1 failed\n");
        return false;
    }
}

int decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int plaintext_len = -1;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return plaintext_len;
    
    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        return plaintext_len;
    
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        goto CLEARUP;
    plaintext_len = len;
    
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        plaintext_len = -1;
        goto CLEARUP;
    }
    plaintext_len += len;

CLEARUP:
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}
