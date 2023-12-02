<?php
namespace SecureTokenPhp;

use InvalidArgumentException;

class Crypto {

    public static function sign(Token $token, ?string $privateKey) {
        $algorithm = $token->getAlgorithm();
        if ($algorithm == Algorithm::none) {
            throw new InvalidArgumentException("signing algorithm cannot be none dumbass");
        }
        return match ($algorithm) {
            algorithm::ES256 => self::SignEs256($token, $privateKey),
            algorithm::HS256 => self::SignHs256($token, $privateKey),
        };
    }

    public static function validate(Token $token, ?string $key = null): bool { 
        return match ($token->getAlgorithm()) { 
            Algorithm::none => true,
            Algorithm::ES256 => self::ValidateEs256($token, $key),
            Algorithm::HS256 => self::ValidateHs256($token, $key),
            null => true
        };
    }

    private static function signEs256(Token $token, string $key): string {
        $privateKeyResource = openssl_pkey_get_private($key);
        if (!$privateKeyResource) {
            throw new \Exception('Invalid private key for ES256 signing.');
        }
        $signature = '';
        $encodedToken = $token->encode();
        openssl_sign($encodedToken, $signature, $privateKeyResource, 'sha256');
        // Base64 encode the signature to make it URL safe
        $encodedSignature = base64_encode($signature);
        $token->set_signature($encodedSignature);
        return $encodedToken . "." . $encodedSignature;
    }


    private static function signHs256(Token $token, string $key) {
        $encodedToken = $token->encode();

        // Create an HMAC with SHA-256
        $binarySignature = hash_hmac('sha256', $encodedToken, $key, true);

        // Base64 encode the signature to make it URL safe
        $encodedSignature = base64_encode($binarySignature);
        $token->set_signature($encodedSignature);

        return $encodedToken . "." . $encodedSignature;
    }


    private static function validateEs256(Token $token, string $publicKey): bool {

        $encodedToken = $token->encode();
        $binarySignature = base64_decode($token->get_signature());
        $publicKeyResource = openssl_pkey_get_public($publicKey);
        if (!$publicKeyResource) {
            throw new \Exception('Invalid public key for ES256 validation.');
        }
        $result = openssl_verify($encodedToken, $binarySignature, $publicKeyResource, 'sha256');
        return $result === 1;
    }

    private static function validateHs256(Token $token, string $key): bool {

        $encodedToken = $token->encode();
        $signatureFromToken = base64_decode($token->get_signature());

        // Recreate the signature using the same method as in signing
        $computedSignature = hash_hmac('sha256', $encodedToken, $key, true);

        // Compare the computed signature with the one in the token
        return hash_equals($computedSignature, $signatureFromToken);
    }

}
