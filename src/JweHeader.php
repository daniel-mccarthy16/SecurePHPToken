<?php

namespace SecureTokenPhp;

/**
 * Represents the header for a JSON Web Encryption (JWE).
 */
class JweHeader extends Header
{
    private const ALGORITHM = 'alg';

    /**
     * Sets the key management algorithm used for the JWE.
     *
     * @param JweAlgorithmEnum $algo The algorithm enum value.
     * @return void
     */
    public function setAlgorithm(JweAlgorithmEnum $algo): void
    {
        $this->headers[self::ALGORITHM] = $algo->value;
    }

    /**
     * Retrieves the key management algorithm set for the JWE, if any.
     *
     * @return JweAlgorithmEnum|null The key management algorithm or null if not set.
     */
    public function getAlgorithm(): ?JweAlgorithmEnum
    {
        $algValue = $this->headers[self::ALGORITHM] ?? null;
        return $algValue !== null ? JweAlgorithmEnum::tryFrom($algValue) : null;
    }

    /**
     * Sets the content encryption algorithm used for the JWE.
     *
     * @param JweContentEncryptionEnum $algo The content encryption algorithm enum value.
     * @return void
     */
    public function setEncAlgorithm(JweContentEncryptionEnum $algo): void
    {
        $this->headers['enc'] = $algo->value;
    }

    /**
     * Retrieves the content encryption algorithm set for the JWE, if any.
     *
     * @return JweContentEncryptionEnum|null The content encryption algorithm or null if not set.
     */
    public function getEncAlgorithm(): ?JweContentEncryptionEnum
    {
        $algValue = $this->headers['enc'] ?? null;
        return $algValue !== null ? JweContentEncryptionEnum::tryFrom($algValue) : null;
    }
}
