<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\InvalidHeaderException;

class JweHeader extends Header
{
    private const ALGORITHM = 'alg';
    private const TYPE = 'typ';


    public function setAlgorithm(JweAlgorithmEnum $algo)
    {
        $this->headers[self::ALGORITHM] = $algo->value;
    }


    public function getAlgorithm(): ?JweAlgorithmEnum
    {
        $algValue = $this->headers['alg'] ?? null;
        return $algValue !== null ? JweAlgorithmEnum::tryFrom($algValue) : null;
    }

    public function setEncAlgorithm(JweContentEncryptionEnum $algo)
    {
        $this->headers['enc'] = $algo->value;
    }


    public function getEncAlgorithm(): ?JweContentEncryptionEnum
    {
        $algValue = $this->headers['enc'] ?? null;
        return $algValue !== null ? JweContentEncryptionEnum::tryFrom($algValue) : null;
    }
}
