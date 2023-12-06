<?php

namespace SecureTokenPhp;

//AEAD algorithms
enum JweContentEncryptionEnum : string
{
    // case A128CBC_HS256 = 'A128CBC-HS256';
    // case A192CBC_HS384 = 'A192CBC-HS384';
    // case A256CBC_HS512 = 'A256CBC-HS512';
    case A128GCM = 'A128GCM';
    // case A192GCM = 'A192GCM';
    case A256GCM = 'A256GCM';
}
