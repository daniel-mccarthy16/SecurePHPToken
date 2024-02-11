<?php

namespace SecureTokenPhp;

use OpenSSLAsymmetricKey;
use SecureTokenPhp\Exceptions\CryptoException;

abstract class Token
{
    protected Payload $payload;
    protected ?string $binarySignature = null;
    protected ?OpenSSLAsymmetricKey $privateKey = null;
    protected ?OpenSSLAsymmetricKey $publicKey = null;
    protected ?string $symmetricKey = null;

    private function __construct()
    {
        // Private constructor to force using factory methods
    }

    abstract public static function fromEncoded(string $serializedToken): Token;

    public function getClaim(string $claimName): ?string
    {
        return $this->payload->getClaim($claimName);
    }

    public function setClaim(string $claimName, string $claimValue): void
    {
         $this->payload->setClaim($claimName, $claimValue);
    }

    public function signToken()
    {
        Crypto::sign(token: $this);
    }


    public function getPayload(): Payload
    {
        return $this->payload;
    }

    public function setPayload(Payload $payload): void
    {
         $this->payload = $payload;
    }

    public function getEncodedPayload(): string
    {
        return $this->payload->encode();
    }

    public function getSignatureBinary(): ?string
    {
        return $this->binarySignature;
    }

    public function getEncodedSignature(): ?string
    {
        if ($this->binarySignature === null) {
            throw new \InvalidArgumentException("binarySignature does not exist");
        }
        return Utility::fileSystemSafeBase64($this->binarySignature);
    }

    public function setSignature(string $binarySignature)
    {
        $this->binarySignature = $binarySignature;
    }

    abstract public function encode(): string;


    public function encodeWithSignature(): string
    {
        return $this->encode() . "." . $this->getEncodedSignature();
    }

    public function setPrivateKey(string $key): void
    {
        //todo catch generic type error and throw below exception
        $this->privateKey = openssl_get_privatekey($key);
        if (!$this->privateKey) {
            throw new CryptoException("key provided not valid");
        }
    }

    public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
        return $this->privateKey;
    }

    public function getPrivateKeyOrThrow(): ?OpenSSLAsymmetricKey
    {
        $key =  $this->privateKey;
        if ($key === null) {
            throw new CryptoException("Please set your encryption key on token");
        }
        return $key;
    }

    public function setPublicKey(string $key): void
    {
        //todo catch generic type error and throw below exception
        $this->publicKey = openssl_get_publickey($key);
        if (!$this->publicKey) {
            throw new CryptoException("Failed to process the public key.");
        }
    }

    public function getPublicKey(): ?OpenSSLAsymmetricKey
    {
        return $this->publicKey;
    }

    public function getPublicKeyOrThrow(): ?OpenSSLAsymmetricKey
    {
        $key =  $this->publicKey;
        if ($key === null) {
            throw new CryptoException("Please set your public key on the token");
        }
        return $key;
    }

    public function setSymmetricalKey(string $key): void
    {
        $this->symmetricKey = $key;
    }

    public function getSymmetricalKey(): ?string
    {
        return $this->symmetricKey;
    }

    public function getSymmetricalKeyOrThrow(): string
    {
        $key =  $this->symmetricKey;
        if ($key === null) {
            throw new CryptoException("Please set your symmetric key on the token");
        }
        return $key;
    }
}
