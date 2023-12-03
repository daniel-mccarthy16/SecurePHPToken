<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\InvalidHeaderException;

class Header
{
    private array $headers = [];

    private const ALGORITHM = 'alg';
    private const TYPE = 'typ';
    private const CONTENT_TYPE = 'cty';
    private const JWK_SET_URL = 'jku';
    private const JSON_WEB_KEY = 'jku';
    private const KEY_ID = 'kid';
    private const X509_URL = 'x5u';
    private const X5C_CERTIFICATE_CHAIN = 'x5u';
    private const CRITICAL = 'crit';

    public static function fromEncoded(string $encodedHeader): self
    {
        $instance = new self();
        $decodedData = json_decode(base64_decode($encodedHeader), associative: true);
        if (!is_array($decodedData)) {
            throw new InvalidHeaderException(
                sprintf('Could not successfully decode the following into a header %s', $encodedHeader)
            );
        }
        $instance->headers = $decodedData;
        return $instance;
    }

    public static function fromUnencoded(?array $headers): self
    {
        $instance = new self();
        if ($headers !== null) {
            $instance->headers = $headers;
        }
        return $instance;
    }

    public function setType(string $type)
    {
        $this->headers[self::TYPE] = $type;
    }

    public function getType(): ?string
    {
        return $this->headers[self::TYPE] ?? null;
    }

    public function setAlgorithm(Algorithm $algo)
    {
        $this->headers[self::ALGORITHM] = $algo->value;
    }


    public function getAlgorithm(): ?Algorithm
    {
        $algValue = $this->headers['alg'] ?? null;
        return $algValue !== null ? Algorithm::tryFrom($algValue) : null;
    }

    // Set a custom header field
    public function setCustomHeader(string $name, $value)
    {
        $this->headers[$name] = $value;
    }

    // Get a custom header field
    public function getCustomHeader(string $name)
    {
        return $this->headers[$name] ?? null;
    }

    //remove "=" padding and replace + and / with - and _ to make url safe
    public function encode(): string
    {
        return rtrim(strtr(base64_encode(json_encode($this->headers)), '+/', '-_'), '=');
    }

    private function isValidMediaType(string $mediaType): bool
    {
        if (strpos($mediaType, '/') === false) {
            return false;
        }
        list ($type, $subtype) = explode('/', $mediaType, 2);
        if (empty($type) || empty($subtype)) {
            return false;
        }
        return true;
    }
}
