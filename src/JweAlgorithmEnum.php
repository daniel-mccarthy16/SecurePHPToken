<?php

namespace SecureTokenPhp;

enum JweAlgorithmEnum : string
{
    // case RSA1_5 = 'RSA1_5';
    case RSA_OAEP = 'RSA-OAEP';
    // case RSA_OAEP_256 = 'RSA-OAEP-256';
    // case A128KW = 'A128KW';
    // case A192KW = 'A192KW';
    // case A256KW = 'A256KW';
    // case dir = 'dir';
    case ECDH_ES = 'ECDH-ES';
    // case ECDH_ES_A128KW = 'ECDH-ES+A128KW';
    // case ECDH_ES_A192KW = 'ECDH-ES+A192KW';
    // case ECDH_ES_A256KW = 'ECDH-ES+A256KW';
    // case A128GCMKW = 'A128GCMKW';
    // case A192GCMKW = 'A192GCMKW';
    // case A256GCMKW = 'A256GCMKW';
    // case PBES2_HS256_A128KW = 'PBES2-HS256+A128KW';
    // case PBES2_HS384_A192KW = 'PBES2-HS384+A192KW';
    // case PBES2_HS512_A256KW = 'PBES2-HS512+A256KW';
}
