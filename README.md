# ChromeCookieDecryptor

Decrypt cookie values in Chrome Sqlite DB on OX S, use Openssl

## Dependencies

openssl, sqlite3. Almost all, they have installed on mac os x.

## Build

```bash
g++ ChromeCookieDecrypt.cpp -lsqlite3 -lcrypto -o chrome_decrytor
```

## Usage

```bash
chrome_decrytor chrome_master_key
```

## Example

```bash
#Extract Chrome master key from keychain
security find-generic-password -ga "Chrome"
#class: "genp"
#attributes:
#0x00000007 <blob>="Chrome Safe Storage"
#0x00000008 <blob>=<NULL>
#....
#password: "nl1kEr58hs33ALHmIyxHqQ=="


#Copy password from above cmd exec result
./chrome_decrytor nl1kEr58hs33ALHmIyxHqQ==
```
