<?php

namespace SecureTokenPhp;

class JwsHeader extends Header
{
    private const ALGORITHM = 'alg';

    public function setAlgorithm(JwsAlgorithmEnum $algo)
    {
        $this->headers[self::ALGORITHM] = $algo->value;
    }


    public function getAlgorithm(): ?JwsAlgorithmEnum
    {
        $algValue = $this->headers['alg'] ?? null;
        return $algValue !== null ? JwsAlgorithmEnum::tryFrom($algValue) : null;
    }
}
