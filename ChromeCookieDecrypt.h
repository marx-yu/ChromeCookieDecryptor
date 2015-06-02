//
//  ChromeCookieDecrypt.h
//
//  Created by yuyg on 15/6/2.
//  Copyright (c) 2015 emacle. All rights reserved.
//

#ifndef synccore_ChromeCookieDecrypt_h
#define synccore_ChromeCookieDecrypt_h
#include <string>
using std::string;

bool DecryptChromeCookie(const string& password, const string &enc_value, string *dec_value);

#endif
