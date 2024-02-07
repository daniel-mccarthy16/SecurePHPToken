# SecurePHPToken

## Description
`daniel/secure-token-php` is a comprehensive PHP JWT solution designed for creating and managing JSON Web Tokens (JWT). This library offers robust support for both JSON Web Encryption (JWE) and JSON Web Signatures (JWS), providing a versatile toolset for secure token management in PHP applications.

### Disclaimer
This project is mainly for educational purposes and should be used accordingly.

## Features
- Support for JWE and JWS token creation and validation.
- Integrates with modern PHP development tools and practices.
- PSR-4 autoloading compliant.

## Installation
To install the library, run the following command in your project directory:

```bash
composer require daniel/secure-token-php
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

This section provides examples of how to create and validate JWE and JWS tokens using `daniel/secure-token-php`.

### Creating a HS256 Token

HS256 (HMAC with SHA-256) is a symmetric algorithm recommended by the [JWS specification (RFC 7518)](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1) for generating JSON Web Signatures. It uses a single secret key for both signing and verifying the token, ensuring the integrity and authenticity of the token's payload.

#### How to Create a HS256 Token 

```php
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
```

### JWE Token Creation and Validation
```php
// Sample code for JWE token creation and validation
