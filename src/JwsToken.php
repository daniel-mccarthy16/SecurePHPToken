<?php

namespace SecureTokenPhp;

class JwsToken extends Token
{
    protected JwsHeader $header;

    public function __construct(?JwsHeader $header = null, ?Payload $payload = null, ?string $binarySignature = null)
    {
        $this->header = $header ?? new JwsHeader();
        $this->payload = $payload ?? new Payload();
        $this->binarySignature = $binarySignature;
    }

    public static function fromEncoded(
        string $serializedToken,
        ?string $publicKey = null,
        ?string $privateKey = null,
        ?string $symmetricKey = null
    ): self {
        $parts = Utility::splitSerializedToken($serializedToken);
        if (count($parts) !== 3 && count($parts) !== 2) {
            throw new \InvalidArgumentException("Serialized JWS token expected to have two or three parts");
        }
        [ $encodedHeader, $encodedPayload, $encodedSignature ] = $parts;
        $instance = new self();
        if ($privateKey !== null) {
            $instance->setPrivateKey($privateKey);
        }
        if ($publicKey !== null) {
            $instance->setPublicKey($publicKey);
        }

        if ($symmetricKey !== null) {
            $instance->setSymmetricalKey($symmetricKey);
        }

        $instance->header = Header::fromEncoded($encodedHeader);
        $instance->payload = Payload::fromEncoded($encodedPayload);

        if ($encodedSignature !== null) {
            $instance->binarySignature = Utility::decodeFileSystemSafeBase64($encodedSignature);
        }
        Crypto::validate($instance);
        return $instance;
    }




    public function encode(): string
    {
        return $this->header->encode() . "." . $this->payload->encode();
    }


    public function getAlgorithm(): JwsAlgorithmEnum
    {
        return $this->header->getAlgorithm();
    }
}
