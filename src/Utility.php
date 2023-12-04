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
}
