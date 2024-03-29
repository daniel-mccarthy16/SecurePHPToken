# SecurePHPToken

## Description
`danielmccarthy/secure-token-php` is a comprehensive PHP JWT solution designed for creating and managing JSON Web Tokens (JWT). This library offers robust support for both JSON Web Encryption (JWE) and JSON Web Signatures (JWS), providing a versatile toolset for secure token management in PHP applications.

### Disclaimer
This project is mainly for educational purposes and should be used accordingly.

## Features
- Support for JWE and JWS token creation and validation.
- Designed to be lightweight with **no runtime dependencies**, ensuring easy integration into any PHP project without adding overhead.
- Full compliance with the JSON Web Token (JWT), JSON Web Signature (JWS), and JSON Web Encryption (JWE) specifications.

## Installation

The `danielmccarthy/secure-token-php` library is currently in its alpha stages and will be available for installation via Composer once it's officially released on Packagist. 

### Future Installation Steps

Once the library is available on Packagist, you will be able to install it by running the following command in your project directory:

```bash
composer require danielmccarthy/secure-token-php
```

## Requirements
- PHP ^8.1


## Supported Token types
| Token Type | Algorithm                | Description                                                                         |
|------------|--------------------------|-------------------------------------------------------------------------------------|
| JWE        | RSA_OAEP & A256GCM       | Uses RSA OAEP for key management and AES GCM with a 256-bit key for content encryption. |
| JWS        | HS256 (HMAC with SHA-256)| Symmetric algorithm using HMAC with SHA-256 for token signing and verification.     |
| JWS        | ES256 (ECDSA with SHA-256)| Uses ECDSA with P-256 curve and SHA-256 for signing and verifying tokens.            |


## When to Use

Each algorithm serves specific purposes in token management and security. Here's a brief guide on when to use each:

1. **HMAC256 (HS256)**
   - **Use when**: You want server-side only verification of token integrity and authenticity. Ideal for scenarios where token information can be public, but you need to ensure it hasn't been tampered with. Best for internal systems where the token issuer and verifier are the same or share a secret key.

2. **ES256**
   - **Use when**: Both client-side and server-side verification is needed without exposing the signing key. Suitable for distributed systems where different parties need to independently verify the token. The information in the token can be public, and the security relies on the infeasibility of deriving the private key from the public key.

3. **RSA_OAEP & A256GCM (JWE)**
   - **Use when**: You need to encrypt the token's content, ensuring it remains confidential and tamper-proof. This algorithm combines RSA's key management (using asymmetric keys for encryption/decryption) with AES's strong content encryption. Ideal for protecting sensitive data within the token, suitable for scenarios where the token payload must be kept secret from unauthorized parties.

## Usage

This section provides examples of how to create and validate JWE and JWS tokens using `danielmccarthy/secure-token-php`.

### HS256 Tokens

HS256 (HMAC with SHA-256) is a symmetric algorithm and holds a unique position as the only one designated as 'required' for implementation in the JSON Web Algorithms (JWA) specification (RFC 7518).  It uses a single secret key for both signing and verifying the token, ensuring the integrity and authenticity of the token's payload and making it a universally accepted choice in various security-related applications.

#### How to create, validate, encode and decode a HS256 Token 

```php
use SecureTokenPhp\JwsToken;
use SecureTokenPhp\JwsHeader;
use SecureTokenPhp\Crypto;
use SecureTokenPhp\Payload;

$payload = new Payload();
$payload->setClaim(claimName: "name", claimValue: "jimbob");

$header = new JwsHeader();
$header->setAlgorithm(JwsAlgorithmEnum::HS256);

$token = new JwsToken(header: $header, payload: $payload);
$token->setSymmetricalKey($mysecretkey);
$token->signToken();

//validate newly created token
$this->assertTrue(Crypto::validate(token: $token));
//retrieve claim
$this->assertEquals($token->getClaim("name"), "jimbob");


//serialize token
$encodedToken = $this->encodeWithSignature()
$this->assertIsString($serializedToken);

//deserialize token
$deserializedToken = JwsToken::fromEncoded($encodedToken, symmetricKey: $mysecretkey);
$this->assertEquals($token->getClaim("name"), "jimbob");
```

### ES256 Tokens

ES256 (ECDSA using P-256 and SHA-256) is endorsed as 'recommended+' in the JSON Web Algorithms (JWA) specification (RFC 7518). This asymmetric algorithm employs a private key for signing and a public key for verification, enhancing security through key separation. ES256 leverages elliptic curve cryptography, offering strong security with smaller keys and efficient processing. Ideal for systems prioritizing security with minimal resource usage.

#### How to create, validate, encode and decode a ES256 Token 

```php
use SecureTokenPhp\JwsToken;
use SecureTokenPhp\JwsHeader;
use SecureTokenPhp\Crypto;
use SecureTokenPhp\Payload;

$payload = new Payload();
$payload->setClaim(claimName: "name", claimValue: "jimbob");

$header = new JwsHeader();
$header->setAlgorithm(JwsAlgorithmEnum::ES256);

$token = new JwsToken(header: $header, payload: $payload);
$token->setPrivateKey($myprivatekey); 
$token->setPublicKey($mypublickey);  
$token->signToken();

//validate newly created token
$this->assertTrue(Crypto::validate(token: $token), publicKey: $mypublickey);
//retrieve claim
$this->assertEquals($token->getClaim("name"), "jimbob");

//serialize token
$encodedToken = $this->encodeWithSignature()
$this->assertIsString($serializedToken);

//deserialize token
$deserializedToken = JwsToken::fromEncoded($encodedToken, publicKey: $mypublickey);
$this->assertEquals($token->getClaim("name"), "jimbob");
```

### JWE Token Creation and Validation
JWE (JSON Web Encryption) tokens provide a secure way to encapsulate claims or payloads, ensuring confidentiality through encryption. The JWA specification recommends several algorithms for encrypting content, with RSA_OAEP & A256GCM being a popular choice due to its strong security properties. RSA_OAEP is used for encrypting the key, and A256GCM for encrypting the payload, offering both privacy and integrity protection.

#### How to Create a JWE Token with RSA_OAEP & A256GCM

```php
use SecureTokenPhp\JweToken;
use SecureTokenPhp\Payload;
use SecureTokenPhp\Crypto;

// Initialize payload with claims
$payload = new Payload();
$payload->setClaim(claimName: "name", claimValue: "jimbob");

// Create a new JWE token and set algorithms
$token = new JweToken();
$token->setContentEncryptionAlgorithm(JweContentEncryptionEnum::A256GCM);
$token->setKeyManagementAlgorithm(JweAlgorithmEnum::RSA_OAEP);

// Note: In a real-world scenario, the public key is used by the sender to encrypt the token for the recipient. 
// The recipient then uses their private key to decrypt the token.
$token->setPrivateKey(file_get_contents(__DIR__ . '/../path/to/rsa_private_key.pem'));
$token->setPublicKey(file_get_contents(__DIR__ . '/../path/to/rsa_public_key.pem'));

// Encrypt the token
$token->encrypt();

// Serialize the token
$serializedJwe = $token->encode();
$this->assertIsString($serializedJwe);

// To validate and decrypt the token
$deserializedToken = JweToken::fromEncoded($serializedJwe);
$deserializedToken->setPrivateKey($privateKey);
Crypto::decrypt($deserializedToken);

// Access decrypted claims
$this->assertEquals($token->getClaim("name"), "jimbob");
```

## Development Commands

This library includes a set of Composer scripts to facilitate development and testing. You can execute these commands from the terminal to perform various tasks:

- **Testing**: Run all unit tests to ensure the library functions as expected.
  ```sh
  composer test
  ```
- **Linting**: Check the code for syntax errors and ensure it adheres to PHP's best practices. This helps maintain code quality and consistency.
  ```sh
  composer lint
  ```
- **Code Formatting**: Automatically check and fix code formatting to comply with the PSR-12 coding standard, which is a set of guidelines for writing clean and readable PHP code.
```sh
  composer check-format
  composer check-style
```
