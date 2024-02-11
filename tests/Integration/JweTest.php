<?php

namespace SecureTokenPhp\Tests;

use PHPUnit\Framework\TestCase;
use SecureTokenPhp\JweToken;
use SecureTokenPhp\Crypto;
use SecureTokenPhp\JweAlgorithmEnum;
use SecureTokenPhp\JweContentEncryptionEnum;

final class JweTest extends TestCase
{
    private const CLAIM_A_NAME = "claimA";
    private const CLAIM_A_VALUE = "A";
    private const CLAIM_B_NAME = "claimB";
    private const CLAIM_B_VALUE = "B";

    /**
     * @test
     * test unsecured jwt token creation and validation
     */
    public function createAndValidateRsa0aepA256GCMToken()
    {
        $token = new JweToken();
        $token->getPayload()->setClaim(claimName: self::CLAIM_A_NAME, claimValue: self::CLAIM_A_VALUE);
        $token->getPayload()->setClaim(claimName: self::CLAIM_B_NAME, claimValue: self::CLAIM_B_VALUE);
        $token->setContentEncryptionAlgorithm(JweContentEncryptionEnum::A256GCM);
        $token->setKeyManagementAlgorithm(JweAlgorithmEnum::RSA_OAEP);
        $privateKey = file_get_contents(__DIR__ . '/../DummyKeys/rsaPrivate2048.pem');
        if (!$privateKey) {
            throw new \Exception("Couldnt read private key");
        };
        $publicKey = file_get_contents(__DIR__ . '/../DummyKeys/rsaPublic2048.pem');
        if (!$publicKey) {
            throw new \Exception("Couldnt read public key");
        }
        $token->setPublicKey($publicKey);
        $token->encrypt();

        $serializedJwe = $token->encode();

        $deserializedToken = JweToken::fromEncoded($serializedJwe);
        $deserializedToken->setPrivateKey($privateKey);
        Crypto::decrypt($deserializedToken);
        $this->assertInstanceOf(JweToken::class, $deserializedToken);
        $this->assertEquals(
            $deserializedToken->getClaim(self::CLAIM_A_NAME),
            self::CLAIM_A_VALUE,
            'Claim A should match.'
        );
        $this->assertEquals(
            $deserializedToken->getClaim(self::CLAIM_B_NAME),
            self::CLAIM_B_VALUE,
            'Claim B should match.'
        );
    }
}
