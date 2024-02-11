<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\InvalidHeaderException;

abstract class Header
{
    protected array $headers = [];

    private const ALGORITHM = 'alg';
    private const TYPE = 'typ';

    /**
     * Constructs a header object from an encoded string.
     *
     * @param string $encodedHeader Base64Url encoded header.
     * @return self Returns an instance of JweHeader or JwsHeader based on the encoded data.
     * @throws InvalidHeaderException If the header is invalid or cannot be decoded.
     */
    public static function fromEncoded(string $encodedHeader): self
    {
        try {
            $base64DecodedHeader = Utility::decodeFileSystemSafeBase64($encodedHeader);
            $decodedData = Utility::jsonDecode($base64DecodedHeader);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidHeaderException($e->getMessage(), 0, $e);
        }

        return self::getHeaderType($decodedData) === JweHeader::class
               ? new JweHeader($decodedData)
               : new JwsHeader($decodedData);
    }

    /**
     * Header constructor.
     *
     * @param array $headers Initial header values.
     */
    public function __construct(array $headers = [])
    {
        $this->headers = $headers;
    }

    /**
     * Creates a header instance from an unencoded array.
     *
     * @param ?array $headers Array of headers.
     * @return self Instance of the header.
     */
    public static function fromUnencoded(?array $headers): self
    {
        // Note: Updated to reflect abstract nature and instantiation logic.
        throw new \LogicException('Method fromUnencoded must be implemented in subclass.');
    }

    /**
     * Sets the "typ" header to indicate the token's media type.
     *
     * @param string $type Media type for the "typ" header, defaults to "JWT".
     */
    public function setType(string $type = 'JWT'): void
    {
        $this->headers[self::TYPE] = $type;
    }

    /**
     * Retrieves the "typ" header value, if set.
     *
     * @return ?string The "typ" header value or null if not set.
     */
    public function getType(): ?string
    {
        return $this->headers[self::TYPE] ?? null;
    }

    /**
     * Retrieves a custom header field by name.
     *
     * @param string $name Name of the header to retrieve.
     * @return ?string Value of the header or null if not found.
     */
    public function getCustomHeader(string $name): ?string
    {
        return $this->headers[$name] ?? null;
    }

    /**
     * Encodes the headers to a base64Url string.
     *
     * @return string Encoded header string.
     */
    public function encode(): string
    {
        return Utility::fileSystemSafeBase64(json_encode($this->headers));
    }

    /**
     * Analyzes headers to determine token type (JWE or JWS).
     *
     * @param array $headers Headers to analyze.
     * @return string Returns JweHeader::class or JwsHeader::class based on the presence of 'enc'.
     */
    private static function getHeaderType(array $headers): string
    {
        return isset($headers['enc']) ? JweHeader::class : JwsHeader::class;
    }
}
