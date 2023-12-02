<?php
namespace SecureTokenPhp;


class Header {

    private array $headers = [];

    public static function fromEncoded(string $encodedHeader): self {
        $instance = new self();
        $instance->headers = base64_decode(json_decode($encodedHeader));
        return $instance;
    }

    public function setType(string $type) {
        $this->headers['typ'] = $type;
    }

    public function getType(): ?string {
        return $this->headers['typ'] ?? null;
    }

    public function setAlgorithm(Algorithm $algo) {
        $this->headers['alg'] = $algo->value;
    }


    public function getAlgorithm(): ?Algorithm {
        $algValue = $this->headers['alg'] ?? null;
        return $algValue !== null ? Algorithm::tryFrom($algValue) : null;
    }

    // Set a custom header field
    public function setCustomHeader(string $name, $value) {
        $this->headers[$name] = $value;
    }

    // Get a custom header field
    public function getCustomHeader(string $name) {
        return $this->headers[$name] ?? null;
    }

    // convert the headers to an array
    public function encode(): string {
        return base64_encode(json_encode($this->headers));
    }


}


