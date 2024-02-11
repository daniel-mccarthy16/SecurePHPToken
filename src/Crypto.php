<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\CryptoException;

class Crypto
{
    public static function sign(JwsToken $token)
    {
        $algorithm = $token->getAlgorithm();
        if ($algorithm == JwsAlgorithmEnum::none) {
            throw new CryptoException(
                "Please configure a signing algorithm on your token before attempting to sign it."
            );
        }
        return match ($algorithm) {
            JwsAlgorithmEnum::ES256 => self::SignEs256($token),
            JwsAlgorithmEnum::HS256 => self::SignHs256($token),
        };
    }

    public static function validate(JwsToken $token): bool
    {
        return match ($token->getAlgorithm()) {
            JwsAlgorithmEnum::none => true,
            JwsAlgorithmEnum::ES256 => self::ValidateEs256($token),
            JwsAlgorithmEnum::HS256 => self::ValidateHs256($token),
            null => true
        };
    }

    private static function signEs256(Token $token): string
    {
        $key = $token->getPrivateKeyOrThrow();
        $binarySignature = '';
        $encodedToken = $token->encode();
        openssl_sign($encodedToken, $binarySignature, $key, 'sha256');
        // Base64 encode the signature to make it URL safe
        $token->setSignature($binarySignature);
        return $encodedToken . "." . $token->getEncodedSignature();
    }

    private static function validateEs256(Token $token): bool
    {
        $key = $token->getPublicKeyOrThrow();
        $encodedToken = $token->encode();
        $binarySignature = $token->getSignatureBinary();
        $result = openssl_verify($encodedToken, $binarySignature, $key, 'sha256');
        return $result === 1;
    }

    private static function signHs256(Token $token): string
    {
        $key = $token->getSymmetricalKey();
        $encodedToken = $token->encode();
        $binarySignature = hash_hmac('sha256', data: $encodedToken, key: $key, binary: true);
        $token->setSignature($binarySignature);
        return $encodedToken . "." . $token->getEncodedSignature();
    }

    private static function validateHs256(Token $token, ?string $key = null): bool
    {
        $key = $token->getSymmetricalKeyOrThrow();
        $encodedToken = $token->encode();
        $signatureFromToken = $token->getSignatureBinary();
        $computedSignature = hash_hmac('sha256', data: $encodedToken, key: $key, binary: true);
        return hash_equals($computedSignature, $signatureFromToken);
    }


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
