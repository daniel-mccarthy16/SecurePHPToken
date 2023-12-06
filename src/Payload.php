<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\InvalidPayloadException;

class Payload
{
    private $claims = [];

    private const ISS = "iss";
    private const SUB = "sub";
    private const EXP = "exp";
    private const NBF = "nbf";
    private const IAT = "iat";
    private const JTI = "jti";
    private const AUD = "aud";



    public function __construct(array $claims = [])
    {
        $this->claims = $claims;
    }

    public static function fromEncoded(string $encodedPayload): self
    {

        try {
            $base64DecodedPayload = Utility::decodeFileSystemSafeBase64($encodedPayload);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidPayloadException($e);
        }


        try {
            $decodedData = Utility::jsonDecode($base64DecodedPayload);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidPayloadException($e);
        }

        $instance = new self();
        $instance->claims = $decodedData;
        return $instance;
    }

    /**
     * Set the "iss" (Issuer) claim, which should be a case-sensitive string.
     *
     * @param string $iss The Issuer value as a case-sensitive string.
     * @throws InvalidArgumentException If the input is not a valid string.
     */
    public function setIssuer(string $iss)
    {
        if ($iss === '') {
            throw new \InvalidArgumentException('Issuer "iss" cannot be an empty string.');
        }

        // Additional validation can be added here if needed

        $this->claims[self::ISS] = $iss;
    }

    /**
     *
     * @return string|null the issuer of the jwt.
     */
    public function getIssuer(): ?string
    {
        return $this->claims[self::ISS] ?? null;
    }

     /**
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
     * @param string $sub the sub of the jwt.
     */
    public function setSubject(string $sub)
    {
        $this->claims[self::SUB] = $sub;
    }

    /**
     * get the sub (sub) claim.
     *
     * @return string|null the sub of the jwt.
     */
    public function getSubject(): ?string
    {
        return $this->claims[self::SUB] ?? null;
    }

     /**
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     * @param string $aud the aud of the jwt.
     */
    public function setAudience(string $aud)
    {
        $this->claims[self::AUD] = $aud;
    }

    /**
     * get the aud (aud) claim.
     *
     * @return string|null the aud of the jwt.
     */
    public function getAudience(): ?string
    {
        return $this->claims[self::AUD] ?? null;
    }

    /**
     * Set the "exp" (expiration time) claim, identifying the time on or after which the JWT should not be accepted.
     * The value should be a Unix timestamp representing this time.
     *
     * @param int $exp The Unix timestamp for the expiration time.
     * @throws InvalidArgumentException If the provided timestamp is not valid.
     */
    public function setExpiration(int $exp)
    {
        // Check if the timestamp is a valid Unix timestamp
        if ($exp <= 0 || !date('Y-m-d H:i:s', $exp)) {
            throw new \InvalidArgumentException('Invalid Unix timestamp provided for exp.');
        }

        $this->claims[self::EXP] = $exp;
    }

    /**
     * Get the exp (expiration time) claim.
     *
     * @return int|null The expiration time of the JWT as a Unix timestamp, or null if not set.
     */
    public function getExpiration(): ?int
    {
        return $this->claims[self::EXP] ?? null;
    }

    /**
     * Set the "nbf" (not before) claim, identifying the time before which the JWT should not be accepted.
     * The value should be a Unix timestamp representing a future time.
     *
     * @param int $nbf The Unix timestamp for the not-before time.
     * @throws InvalidArgumentException If the provided timestamp is not valid or not in the future.
     */
    public function setNotBefore(int $nbf)
    {
        // Check if the timestamp is a valid Unix timestamp
        if ($nbf <= 0 || !date('Y-m-d H:i:s', $nbf)) {
            throw new \InvalidArgumentException('Invalid Unix timestamp provided for nbf.');
        }

        // Check if the timestamp is in the future
        $currentTimestamp = time();
        if ($nbf <= $currentTimestamp) {
            throw new \InvalidArgumentException('The nbf time must be set in the future.');
        }

        $this->claims[self::NBF] = $nbf;
    }

    /**
     * get the nbf (exp) claim.
     *
     * @return string|null the nbfg of the jwt.
     */
    public function getNotBefore(): ?int
    {
        return $this->claims[self::NBF] ?? null;
    }


    /**
     * Set the "iat" (Issued At) claim to the specified time or to the current time if not specified.
     * The "iat" claim identifies the time at which the JWT was issued and is represented as a NumericDate.
     * If no time is provided, the current server time is used.
     *
     * @param int|null $iat The Unix timestamp when the JWT was issued. Optional.
     */
    public function setIssuedAt(?int $iat = null)
    {
        $this->claims[self::IAT] = $iat ?? time();
    }

    /**
     * Get the iat (Issued At) claim.
     *
     * @return int|null The Issued At time of the JWT as a Unix timestamp, or null if not set.
     */
    public function getIssuedAt(): ?int
    {
        return $this->claims[self::IAT] ?? null;
    }


    /**
     * Set or auto-generate the "jti" (JWT ID) claim.
     * If $jti is provided, it is used; if $jti is null, a unique identifier is auto-generated.
     *
     * @param string|null $jti The JWT ID to set. If null, a unique identifier will be auto-generated.
     */
    public function setJwtId(?string $jti = null)
    {
        if ($jti === null) {
            // Auto-generate a unique JWT ID
            $this->claims[self::JTI] = Utility::generateUniqueId();
        } else {
            // Use the provided JWT ID
            $this->claims[self::JTI] = $jti;
        }
    }

    /**
     * get the jti (exp) claim.
     *
     * @return string|null the jtig of the jwt.
     */
    public function getJwdId(): ?string
    {
        return $this->claims[self::JTI] ?? null;
    }


    /**
     * Dump all claims
     *
     * @return array
     */
    public function getAllClaims(): array
    {
        return $this->claims;
    }

    /**
     * Set a custom claim or a claim that is not defined as registered by RFC 7519.
     * This method can be used to set claims without the restrictions imposed by the setters for registered claims.
     * Useful for special cases where non-standard or additional claims are required.
     *
     * @param string $claimName The name of the claim to set.
     * @param string $claimValue The value of the claim.
     */
    public function setClaim(string $claimName, string $claimValue)
    {
        $this->claims[$claimName] = $claimValue;
    }

    /**
     * Get the value of a specific claim by its name.
     * This method can be used to retrieve both registered and custom claims.
     * Returns null if the specified claim is not present in the JWT.
     *
     * @param string $claimName The name of the claim to retrieve.
     * @return string|null The value of the claim, or null if it is not set.
     */
    public function getClaim(string $claimName): ?string
    {
        return $this->claims[$claimName] ?? null;
    }

    public function encode(): string
    {
        return Utility::fileSystemSafeBase64(json_encode($this->claims));
    }
}
