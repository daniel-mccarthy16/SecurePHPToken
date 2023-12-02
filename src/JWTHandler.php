<?php 

namespace SecureTokenPhp;

enum Algorithm : string   {
    case HS256  = 'HS256';
    case none   = 'none';
    case ES256  = 'ES256';
}

class SecureTokenPHP {




}
	



   // +--------------+-------------------------------+--------------------+
   // | "alg" Param  | Digital Signature or MAC      | Implementation     |
   // | Value        | Algorithm                     | Requirements       |
   // +--------------+-------------------------------+--------------------+
   // | HS256        | HMAC using SHA-256            | Required           |
   // | HS384        | HMAC using SHA-384            | Optional           |
   // | HS512        | HMAC using SHA-512            | Optional           |
   // | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
   // |              | SHA-256                       |                    |
   // | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
   // |              | SHA-384                       |                    |
   // | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
   // |              | SHA-512                       |                    |
   // | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
   // | ES384        | ECDSA using P-384 and SHA-384 | Optional           |
   // | ES512        | ECDSA using P-521 and SHA-512 | Optional           |
   // | PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
   // |              | MGF1 with SHA-256             |                    |
   // | PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
   // |              | MGF1 with SHA-384             |                    |
   // | PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
   // |              | MGF1 with SHA-512             |                    |
   // | none         | No digital signature or MAC   | Optional           |
   // |              | performed                     |                    |
   // +--------------+-------------------------------+--------------------+
