<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\InvalidHeaderException;

abstract class Header
{
    protected array $headers = [];

    private const ALGORITHM = 'alg';
    private const TYPE = 'typ';


    public static function fromEncoded(string $encodedHeader): self
    {

        try {
            $base64DecodedHeader = Utility::decodeFileSystemSafeBase64($encodedHeader);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidHeaderException($e);
        }


        try {
            $decodedData = Utility::jsonDecode($base64DecodedHeader);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidHeaderException($e);
        }


        if (self::getHeaderType($decodedData) === JweHeader::class) {
            return new JweHeader($decodedData);
        } else {
            return new JwsHeader($decodedData);
        }
    }

    public function __construct(array $headers = [])
    {
        $this->headers = $headers;
    }

    public static function fromUnencoded(?array $headers): self
    {
        $instance = new self($headers);
        if ($headers !== null) {
            $instance->headers = $headers;
        }
        return $instance;
    }

    private static function getHeaderType(array $headers): string
    {
        if (isset($headers['enc'])) {
            return JweHeader::class;
        } else {
            return JwsHeader::class;
        }
    }

    public function setType(string $type)
    {
        $this->headers[self::TYPE] = $type;
    }

    public function getType(): ?string
    {
        return $this->headers[self::TYPE] ?? null;
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


    public function encode(): string
    {
        return Utility::fileSystemSafeBase64(json_encode($this->headers));
    }
}
