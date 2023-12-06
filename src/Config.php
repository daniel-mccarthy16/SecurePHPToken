<?php

namespace SecureTokenPhp;

class Config
{
    private static $es256KeyPair = null;
    private static $hs256Key = null;

    //DEK encryption keys
    private static $rsaOaepKeyPair = null;

    public static function setEs256KeyPair(string $privateKey, string $publicKey)
    {
        self::$es256KeyPair = ['private' => $privateKey, 'public' => $publicKey];
    }

    public static function setHs256Key(string $key)
    {
        self::$hs256Key = $key;
    }

    public static function getEs256PrivateKey(): ?string
    {
        return self::$es256KeyPair['private'] ?? null;
    }

    public static function getEs256PublicKey(): ?string
    {
        return self::$es256KeyPair['public'] ?? null;
    }

    public static function getHs256Key(): ?string
    {
        return self::$hs256Key;
    }

    public static function setRsaOaepKeyPair(string $privateKey, string $publicKey)
    {
        self::$rsaOaepKeyPair = ['private' => $privateKey, 'public' => $publicKey];
    }

    public static function getRsaOaepPrivateKey(): ?string
    {
        return self::$rsaOaepKeyPair['private'] ?? null;
    }

    public static function getRsaOaepPublicKey(): ?string
    {
        return self::$rsaOaepKeyPair['public'] ?? null;
    }
}
