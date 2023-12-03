<?php

namespace SecureTokenPhp;

class Token
{
    private Header $header;
    private Payload $payload;
    private ?string $binarySignature = null;

    private function __construct()
    {
        // Private constructor to force using factory methods
    }

    public static function fromEncoded(string $serializedToken): self
    {
        $instance = new self();
        [ $encodedHeader, $encodedPayload, $encodedSignature ] = Utility::splitSerializedToken($serializedToken);

        $instance->header = Header::fromEncoded($encodedHeader);
        $instance->payload = Payload::fromEncoded($encodedPayload);

        if ($encodedSignature !== null) {
            //reverse process used to make signature url/filesystem safe
            $decodedSignature = strtr($encodedSignature, '-_', '+/');
            // Add padding if necessary
            $padding = strlen($decodedSignature) % 4;
            if ($padding > 0) {
                $decodedSignature .= str_repeat('=', 4 - $padding);
            }
            $instance->binarySignature = base64_decode($decodedSignature);
        }

        return $instance;
    }

    public static function fromUnencoded(Header $header, Payload $payload, ?string $binarySignature = null): self
    {
        $instance = new self();
        $instance->header = $header;
        $instance->payload = $payload;
        $instance->binarySignature = $binarySignature;
        return $instance;
    }


    public function getClaim(string $claimName): ?string
    {
        return $this->payload->getClaim($claimName);
    }

    public function signToken(?string $privateKey)
    {
        Crypto::sign(token: $this, privateKey: $privateKey);
    }

    public function getHeader(): Header
    {
        return $this->header;
    }


    public function getPayload(): Payload
    {
        return $this->payload;
    }

    public function getEncodedPayload(): string
    {
        return $this->header->encode();
    }

    public function getAlgorithm(): ?Algorithm
    {
        return $this->header->getAlgorithm();
    }

    public function getSignatureBinary(): ?string
    {
        return $this->binarySignature;
    }

    public function getEncodedSignature(): ?string
    {
        return rtrim(strtr(base64_encode($this->binarySignature), '+/', '-_'), '=');
    }

    public function setSignature(string $binarySignature)
    {
        $this->binarySignature = $binarySignature;
    }

    public function encode(): string
    {
        return $this->header->encode() . "." . $this->payload->encode();
    }

    public function encodeWithSignature(): string
    {
        return $this->encode() + "." + $this->getEncodedSignature();
    }
}