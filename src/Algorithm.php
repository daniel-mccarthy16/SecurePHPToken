<?php
namespace SecureTokenPhp;
enum Algorithm : string   {
    case HS256  = 'HS256';
    case none   = 'none';
    case ES256  = 'ES256';
}
