<?php

namespace SecureTokenPhp;

use InvalidArgumentException;
use SecureTokenPhp\Exceptions\TokenSplitException;

class Utility
{
/**
 * Splits a serialized JWT token into its constituent parts.
 *
 * This method splits a JWT token into its header, payload, and signature parts.
 * It expects the token to be in the format of two or three base64 encoded strings
 * separated by dots. It throws an exception if the format is invalid.
 *
 * @param string $serializedToken The serialized JWT token.
 * @return array An array containing the split parts of the token.
 * @throws TokenSplitException If the token does not have a valid number of parts
 */
    public static function splitSerializedToken(string $serializedToken): array
    {
        $parts = explode('.', $serializedToken);
        // Check for two or three parts
        $partsCount = count($parts);
        if ($partsCount !== 3 && $partsCount !== 2 && $partsCount !== 5) {
            throw new TokenSplitException(
                sprintf(
                    'JWS tokens should be represented by 2 or 3 parts, JWE tokens by 5',
                    $serializedToken
                )
            );
        }
        return $parts;
    }
/**
 * Encodes data in a file-system safe base64 format.
 *
 * This method encodes data in base64 while replacing '+' and '/' characters
 * with '-' and '_' respectively, making it safe for file system naming.
 * It also trims any trailing '=' characters.
 *
 * @param string $data The data to be base64 encoded.
 * @return string The base64 encoded string, modified for file-system safety.
 */
    public static function fileSystemSafeBase64(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

/**
 * Decodes a file-system safe base64 encoded string.
 *
 * This method decodes a string that was base64 encoded and made file-system safe
 * by replacing '-' and '_' with '+' and '/'. It also adds '=' characters to make
 * the length of the string a multiple of 4 before decoding. It throws an exception
 * if the input is not valid base64.
 *
 * @param string $data The file-system safe base64 encoded string.
 * @return string The decoded string.
 * @throws InvalidArgumentException If the provided data is not valid base64 encoded.
 */
    public static function decodeFileSystemSafeBase64(string $data): string
    {
        // Add '=' characters until the length of the string is a multiple of 4
        //
        while (strlen($data) % 4 !== 0) {
            $data .= '=';
        }
        $decodedData = base64_decode(strtr($data, '-_', '+/'), strict: true);
        if ($decodedData === false) {
            throw new InvalidArgumentException('The provided data is not valid base64 encoded.');
        }

        return $decodedData;
    }

    /**
     * Generate a unique 32 character long identifier for the JWT ID.
     * @return string The generated unique identifier.
     */
    public static function generateUniqueId(): string
    {
        //Generate a pseudo-random string of bytes and convert it to hexadecimal
        try {
            $bytes = random_bytes(16);
        } catch (\Exception) {
            // Fallback to OpenSSL if random_bytes is not available
            $bytes = openssl_random_pseudo_bytes(16);
        }
        return bin2hex($bytes);
    }

   /**
     * Decodes a JSON string into an associative array.
     *
     * This method decodes a JSON string and throws an exception if the decoding fails.
     *
     * @param string $json The JSON string to decode.
     * @return array The decoded associative array.
     * @throws JsonDecodeException If the JSON string cannot be decoded.
     */
    public static function jsonDecode(string $json): array
    {

        if (!mb_check_encoding($json, 'UTF-8')) {
            throw new InvalidArgumentException('The serialized json string is not valid UTF-8.');
        }

        //TODO - add client config that allows them to pull all their data as an associative array vs stdClass
        $decodedData = json_decode($json, associative: true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException(sprintf(
                'JSON decoding error: %s. Input: %s',
                json_last_error_msg(),
                $json
            ));
        }

        return $decodedData;
    }

    /**
     * Validates a media type string against a standard format.
     *
     * This method checks if the provided media type string conforms to the
     * standard "type/subtype" format, using a regular expression for validation.
     * Both type and subtype components must consist of alphanumeric characters
     * and hyphens only.
     *
     * @param string $mediaType The media type string to validate.
     * @return bool True if the media type is valid, false otherwise.
     */
    public static function isValidMediaType(string $mediaType): bool
    {
        $pattern = '/^[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+$/';
        return preg_match($pattern, $mediaType) === 1;
    }
}
