<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\InvalidHeaderException;

class JwsHeader extends Header
{
    private const ALGORITHM = 'alg';
    private const TYPE = 'typ';



    public function setType(string $type)
    {
        $this->headers[self::TYPE] = $type;
    }

    public function getType(): ?string
    {
        return $this->headers[self::TYPE] ?? null;
    }

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
