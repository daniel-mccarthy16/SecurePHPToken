<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\TokenSplitException;

class Utility
{
    public static function splitSerializedToken(string $serializedToken): array
    {
        $parts = explode('.', $serializedToken);
        // Check for two or three parts
        $partsCount = count($parts);
        if ($partsCount > 3 || $partsCount < 2) {
            throw new TokenSplitException(
                sprintf(
                    'Token should be represented by 2 or 3 base64 encoded parts delimited by dot characters',
                    $serializedToken
                )
            );
        }
        return $parts;
    }

    public static function fileSystemSafeBase64(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }


    public static function decodeFileSystemSafeBase64(string $data): string
    {
        // Add '=' characters until the length of the string is a multiple of 4
        //
        while (strlen($data) % 4 !== 0) {
            $data .= '=';
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Generate a unique identifier for the JWT ID.
     * @return string The generated unique identifier.
     */
    public static function generateUniqueId(): string
    {
        //Generate a pseudo-random string of bytes and convert it to hexadecimal
        try {
            $bytes = random_bytes(16); // 16 bytes will result in a 32 characters hexadecimal string
        } catch (\Exception $e) {
            // Fallback to OpenSSL if random_bytes is not available
            $bytes = openssl_random_pseudo_bytes(16);
        }
        return bin2hex($bytes);
    }
}
