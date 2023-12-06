<?php

namespace SecureTokenPhp;

enum JwsAlgorithmEnum : string
{
    case HS256 = 'HS256';
    case ES256 = 'ES256';
    case none  = 'none';
}
