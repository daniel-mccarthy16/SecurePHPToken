<?php

namespace SecureTokenPhp;

/**
 * Represents the header for a JSON Web Signature (JWS).
 */
class JwsHeader extends Header
{
    private const ALGORITHM = 'alg';

    /**
     * Sets the algorithm used for signing the JWS.
     *
     * @param JwsAlgorithmEnum $algo The signing algorithm.
     * @return void
     */
    public function setAlgorithm(JwsAlgorithmEnum $algo): void
    {
        $this->headers[self::ALGORITHM] = $algo->value;
    }

    /**
     * Retrieves the algorithm used for signing the JWS, if set.
     *
     * @return JwsAlgorithmEnum|null The signing algorithm, or null if not set.
     */
    public function getAlgorithm(): ?JwsAlgorithmEnum
    {
        $algValue = $this->headers[self::ALGORITHM] ?? null;
        return $algValue !== null ? JwsAlgorithmEnum::tryFrom($algValue) : null;
    }
}
