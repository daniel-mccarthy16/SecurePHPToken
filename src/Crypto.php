<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\CryptoException;

class Crypto
{
    /**
     * Signs a JWS token using the specified algorithm.
     *
     * @param JwsToken $token The token to be signed.
     * @return string The signed token as a string.
     * @throws CryptoException If the token's configured algorithm is none or unsupported.
     */
    public static function sign(JwsToken $token): string
    {
        $algorithm = $token->getAlgorithm();
        if ($algorithm == JwsAlgorithmEnum::none) {
            throw new CryptoException(
                "Please configure a signing algorithm on your token before attempting to sign it."
            );
        }
        return match ($algorithm) {
            JwsAlgorithmEnum::ES256 => self::signEs256($token),
            JwsAlgorithmEnum::HS256 => self::signHs256($token),
            default => throw new CryptoException("Unsupported signing algorithm specified."),
        };
    }

    /**
     * Validates a JWS token using its configured algorithm.
     *
     * @param JwsToken $token The token to validate.
     * @return bool True if the token is valid, false otherwise.
     */
    public static function validate(JwsToken $token): bool
    {
        return match ($token->getAlgorithm()) {
            JwsAlgorithmEnum::none => true,
            JwsAlgorithmEnum::ES256 => self::validateEs256($token),
            JwsAlgorithmEnum::HS256 => self::validateHs256($token),
            default => false,
        };
    }

    /**
     * Signs a token using the ES256 algorithm.
     *
     * @param Token $token The token to sign.
     * @return string The signature as a string.
     * @throws CryptoException If the private key is not set or invalid.
     */
    private static function signEs256(Token $token): string
    {
        $key = $token->getPrivateKeyOrThrow();
        $binarySignature = '';
        $encodedToken = $token->encode();
        //TODO - openssl infers the algorithm it will use to encrypt the hash via the key passed in,
        //should make this more explicit (confirm it is actually an eliptical curve key somewhere else)...
        openssl_sign($encodedToken, $binarySignature, $key, OPENSSL_ALGO_SHA256);
        $token->setSignature($binarySignature); // Ensuring the signature is URL safe
        return $encodedToken . "." . base64_encode($binarySignature);
    }

    /**
     * Validates a token using the ES256 algorithm with its public key.
     *
     * @param Token $token The token to validate.
     * @return bool True if the signature is valid, false otherwise.
     * @throws CryptoException If the public key is not set or invalid.
     */
    private static function validateEs256(Token $token): bool
    {
        $key = $token->getPublicKeyOrThrow();
        $encodedToken = $token->encode();
        $binarySignature = $token->getSignatureBinary();
        $result = openssl_verify($encodedToken, $binarySignature, $key, OPENSSL_ALGO_SHA256);
        return $result === 1;
    }
    /**
     * Signs a token using the HS256 algorithm with its symmetric key.
     *
     * @param Token $token The token to sign.
     * @return string The signature as a base64 encoded string.
     * @throws CryptoException If the symmetric key is not set or invalid.
     */
    private static function signHs256(Token $token): string
    {
        $key = $token->getSymmetricalKey();
        $encodedToken = $token->encode();
        $binarySignature = hash_hmac('sha256', data: $encodedToken, key: $key, binary: true);
        $token->setSignature($binarySignature);
        return $encodedToken . "." . $token->getEncodedSignature();
    }

    /**
     * Validates a token using the HS256 algorithm with its symmetric key.
     *
     * @param Token $token The token to validate.
     * @param ?string $key The symmetric key to use for validation. If null, the key is retrieved from the token.
     * @return bool True if the signature is valid, false otherwise.
     * @throws CryptoException If the symmetric key is not set or invalid.
     */
    private static function validateHs256(Token $token, ?string $key = null): bool
    {
        $key = $token->getSymmetricalKeyOrThrow();
        $encodedToken = $token->encode();
        $signatureFromToken = $token->getSignatureBinary();
        $computedSignature = hash_hmac('sha256', data: $encodedToken, key: $key, binary: true);
        return hash_equals($computedSignature, $signatureFromToken);
    }

    /**
     * Encrypts a JWE token using the specified content encryption algorithm.
     *
     * @param JweToken $token The token to encrypt.
     * @return string The encoded JWE token.
     * @throws CryptoException If an unsupported encryption algorithm is specified or encryption fails.
     */
    public static function encrypt(JweToken $token)
    {
        $aeadAlg = $token->getContentEncryptionAlgorithmOrThrow();
        match ($aeadAlg->value) {
            JweContentEncryptionEnum::A256GCM->value  => self::encryptA256GCM($token),
            default => throw new CryptoException("Content encryption algorithm specified not supported")
        };
        self::encryptDek(token: $token);
        return $token->encode();
    }

    /**
     * Decrypts a JWE token using its specified content encryption and key management algorithms.
     *
     * @param JweToken $token The token to decrypt.
     * @return void
     * @throws CryptoException If any required algorithms are not set or unsupported, or if decryption fails.
     */
    public static function decrypt(JweToken $token)
    {
        $enc = $token->getContentEncryptionAlgorithm();
        $enc ?? throw new CryptoException("Content Encryption Algorithm is not set.");

        $alg = $token->getKeyManagementAlgorithm();
        $alg ?? throw new CryptoException("Content Encryption Algorithm is not set.");
        match ($alg->value) {
            JweAlgorithmEnum::RSA_OAEP->value => self::decryptWithRsaOaep($token),
            default => throw new CryptoException("Unsupported key management algorithm")
        };
        match ($enc->value) {
            JweContentEncryptionEnum::A256GCM->value  => self::decryptA256GCM($token),
            default => throw new CryptoException("Content Algorithm Encyrption specified not supported")
        };
    }

    /**
     * Encrypts the payload of a JWE token using AES-GCM with a 256-bit key (A256GCM).
     *
     * @param JweToken $token The JWE token to encrypt.
     * @return void
     * @throws CryptoException If encryption fails.
     */
    private static function encryptA256GCM(JweToken $token): void
    {
        $dek  = random_bytes(32);
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $aad = $token->getEncodedHeader(); //include header as additional authenticated data
        $tagLength = 16;

        $ciphertext = openssl_encrypt(
            data: $token->getEncodedPayload(),
            cipher_algo: 'aes-256-gcm',
            passphrase: $dek,
            options: OPENSSL_RAW_DATA,
            iv: $iv,
            tag: $tag,
            aad: $aad,
            tag_length: $tagLength
        );
        if ($ciphertext === null) {
            throw new CryptoException('Encryption failed: ' . openssl_error_string());
        }
        $token->setCipherText($ciphertext);
        $token->setDek($dek);
        $token->setInitializationVector($iv);
        $token->setAuthenticationTag($tag);
    }

    /**
     * Decrypts the payload of a JWE token using AES-GCM with a 256-bit key.
     *
     * @param JweToken $token The JWE token to decrypt.
     * @return void
     * @throws CryptoException If decryption fails or if any cryptographic parameters are invalid.
     */
    private static function decryptA256GCM(JweToken $token): void
    {
        $dek = $token->getDek();
        $iv = $token->getInitializationVector();
        $tag = $token->getAuthenticationTag();
        $aad = $token->getEncodedHeader(); // Assuming the same AAD was used for decryption

        $ciphertext = $token->getCipherText();

        // Decrypt the data
        $decryptedPayload = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $dek,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );

        if ($decryptedPayload === false) {
            throw new CryptoException('Decryption failed: ' . openssl_error_string());
        }

        $token->setPayload(Payload::fromEncoded($decryptedPayload));
    }

    /**
     * Encrypts the Data Encryption Key (DEK) using the specified key management algorithm.
     *
     * @param JweToken $token The JWE token containing the DEK to encrypt.
     * @return void
     * @throws CryptoException If an unsupported key management algorithm is used.
     */
    private static function encryptDEK(JweToken $token): void
    {
        $algorithm = $token->getKeyManagementAlgorithmOrThrow();
        match ($algorithm) {
            JweAlgorithmEnum::RSA_OAEP => self::encryptWithRsaOaep($token),
            default => throw new CryptoException(
                "Unsupported key management algorithm, did you forget to set one for your token?"
            )
        };
    }

    /**
     * Decrypts the encrypted Data Encryption Key (DEK) using RSA-OAEP.
     *
     * @param JweToken $token The JWE token with the DEK to decrypt.
     * @return void
     * @throws CryptoException If the decryption of the DEK fails.
     */
    private static function decryptWithRsaOaep(JweToken $token): void
    {
        //TODO -should padding in here be configurable?
        $privateKey = $token->getPrivateKeyOrThrow();
            $buffer = '';
        if (
            !openssl_private_decrypt(
                data: $token->getEncryptedDek(),
                decrypted_data: $buffer,
                private_key: $privateKey,
                padding: OPENSSL_PKCS1_OAEP_PADDING
            )
        ) {
            throw new CryptoException("Decrypting RSA-OAEP encrypted data encryption key failed");
        }
            $token->setDek($buffer);
    }

    /**
     * Encrypts the Data Encryption Key (DEK) using RSA-OAEP.
     *
     * @param JweToken $token The JWE token containing the DEK to encrypt.
     * @return void
     * @throws CryptoException If the encryption of the DEK fails.
     */
    private static function encryptWithRsaOaep(JweToken $token): void
    {
        $key = $token->getPublicKeyOrThrow();
        $dataEncryptionKey = $token->getDek();
        if (
            !openssl_public_encrypt(
                data: $dataEncryptionKey,
                encrypted_data: $encryptedKey,
                public_key: $key,
                padding: OPENSSL_PKCS1_OAEP_PADDING
            )
        ) {
            throw new CryptoException("Failed to encrypt data encryption key");
        }

        $token->setEncryptedDek($encryptedKey);
    }
}
