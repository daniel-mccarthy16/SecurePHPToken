<?php

namespace SecureTokenPhp;

use SecureTokenPhp\Exceptions\CryptoException;

class JweToken extends Token
{
    protected ?string $encryptedDek = null;
    protected ?string $dek = null;
    protected ?string $initializationVector = null;
    protected ?string $cipherText = null;
    protected ?string $authenticationTag = null;
    protected ?string $recipientPublicKey = null;
    protected JweHeader $header;

    public static function fromEncoded(string $serializedToken): self
    {
        $parts = Utility::splitSerializedToken($serializedToken);
        if (count($parts) !== 5) {
            throw new \InvalidArgumentException("serialized JWE token expected to have 5 parts");
        }
        [ $encodedHeader,  $encodedEncryptedDek, $encodedIv,$encodedCipherText, $encodedAuthenticationTag ] = $parts;
        $instance = new self();
        $instance->header = Header::fromEncoded($encodedHeader);
        $instance->encryptedDek = Utility::decodeFileSystemSafeBase64($encodedEncryptedDek);
        $instance->initializationVector = Utility::decodeFileSystemSafeBase64($encodedIv);
        $instance->cipherText = Utility::decodeFileSystemSafeBase64($encodedCipherText);
        $instance->authenticationTag = Utility::decodeFileSystemSafeBase64($encodedAuthenticationTag);
        return $instance;
    }


    public function __construct(?JweHeader $header = null, ?Payload $payload = null)
    {
        $this->header = $header ?? new JweHeader();
        $this->payload = $payload ?? new Payload();
    }

    public function getKeyManagementAlgorithm(): ?JweAlgorithmEnum
    {
        return $this->header->getAlgorithm();
    }

    public function getKeyManagementAlgorithmOrThrow(): ?JweAlgorithmEnum
    {
        $algorithm = $this->getKeyManagementAlgorithm();
        if ($algorithm === null) {
            throw new CryptoException("missing key management algorithm required to perform envelope encryption");
        }
        return $algorithm;
    }


    public function setKeyManagementAlgorithm(JweAlgorithmEnum $keyManagementAlgorithm): void
    {
        $this->header->setAlgorithm($keyManagementAlgorithm);
    }

    public function getContentEncryptionAlgorithm(): ?JweContentEncryptionEnum
    {
        return $this->header->getEncAlgorithm();
    }

    public function getContentEncryptionAlgorithmOrThrow(): ?JweContentEncryptionEnum
    {
        $algorithm = $this->header->getEncAlgorithm();
        if ($algorithm === null) {
            throw new \Exception("Missing content encryption required to encrypt plain text");
        }
        return $algorithm;
    }


    public function setContentEncryptionAlgorithm(JweContentEncryptionEnum $contentEncryptionAlgorithm): void
    {
        $this->header->setEncAlgorithm($contentEncryptionAlgorithm);
    }


 // Encrypted DEK Getters and Setters
    public function getEncryptedDek(): ?string
    {
        return $this->encryptedDek;
    }

    public function setEncryptedDek(?string $encryptedDek): void
    {
        $this->encryptedDek = $encryptedDek;
    }

    // DEK Getters and Setters
    public function getDek(): ?string
    {
        return $this->dek;
    }

    public function setDek(?string $dek): void
    {
        $this->dek = $dek;
    }

    // Initialization Vector Getters and Setters
    public function getInitializationVector(): ?string
    {
        return $this->initializationVector;
    }

    public function setInitializationVector(?string $initializationVector): void
    {
        $this->initializationVector = $initializationVector;
    }

    // CipherText Getters and Setters
    public function getCipherText(): ?string
    {
        return $this->cipherText;
    }

    public function setCipherText(?string $cipherText): void
    {
        $this->cipherText = $cipherText;
    }

    // Authentication Tag Getters and Setters
    public function getAuthenticationTag(): ?string
    {
        return $this->authenticationTag;
    }

    public function setAuthenticationTag(?string $authenticationTag): void
    {
        $this->authenticationTag = $authenticationTag;
    }


    public function encrypt()
    {
        Crypto::encrypt(token: $this);
    }


    public function getEncodedHeader(): string
    {
        return $this->header->encode();
    }

    public function encode(): string
    {
        return $this->header->encode() .
            "." .
            Utility::fileSystemSafeBase64($this->getEncryptedDek()) .
            "." .
            Utility::fileSystemSafeBase64($this->getInitializationVector()) .
            "." .
            Utility::fileSystemSafeBase64($this->getCipherText()) .
            "." .
            Utility::fileSystemSafeBase64($this->getAuthenticationTag());
    }
}
