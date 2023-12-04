<?php

namespace SecureTokenPhp;

use InvalidArgumentException;

class Crypto
{
    public static function sign(Token $token, ?string $privateKey)
    {
        $algorithm = $token->getAlgorithm();
        if ($algorithm == Algorithm::none) {
            throw new InvalidArgumentException("signing algorithm cannot be none dumbass");
        }
        return match ($algorithm) {
            algorithm::ES256 => self::SignEs256($token, $privateKey),
            algorithm::HS256 => self::SignHs256($token, $privateKey),
        };
    }

    public static function validate(Token $token, ?string $key = null): bool
    {
        return match ($token->getAlgorithm()) {
            Algorithm::none => true,
            Algorithm::ES256 => self::ValidateEs256($token, $key),
            Algorithm::HS256 => self::ValidateHs256($token, $key),
            null => true
        };
    }

    private static function signEs256(Token $token, string $key): string
    {
        $privateKeyResource = openssl_pkey_get_private($key);
        if (!$privateKeyResource) {
            throw new \Exception('Invalid private key for ES256 signing.');
        }
        $binarySignature = '';
        $encodedToken = $token->encode();
        openssl_sign($encodedToken, $binarySignature, $privateKeyResource, 'sha256');
        // Base64 encode the signature to make it URL safe
        $token->setSignature($binarySignature);
        return $encodedToken . "." . $token->getEncodedSignature();
    }

    private static function validateEs256(Token $token, string $publicKey): bool
    {

        $encodedToken = $token->encode();
        $binarySignature = $token->getSignatureBinary();
        $publicKeyResource = openssl_pkey_get_public($publicKey);
        if (!$publicKeyResource) {
            throw new \Exception('Invalid public key for ES256 validation.');
        }
        $result = openssl_verify($encodedToken, $binarySignature, $publicKeyResource, 'sha256');
        return $result === 1;
    }

    private static function signHs256(Token $token, string $key): string
    {
        $encodedToken = $token->encode();
        $binarySignature = hash_hmac('sha256', data: $encodedToken, key: $key, binary: true);
        $token->setSignature($binarySignature);
        return $encodedToken . "." . $token->getEncodedSignature();
    }

    private static function validateHs256(Token $token, string $key): bool
    {
        $encodedToken = $token->encode();
        $signatureFromToken = $token->getSignatureBinary();
        $computedSignature = hash_hmac('sha256', data: $encodedToken, key: $key, binary: true);
        return hash_equals($computedSignature, $signatureFromToken);
    }
}
