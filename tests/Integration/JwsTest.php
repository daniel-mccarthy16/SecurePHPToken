<?php

namespace SecureTokenPhp\Tests;

use PHPUnit\Framework\TestCase;
use SecureTokenPhp\JwsAlgorithmEnum;
use SecureTokenPhp\Token;
use SecureTokenPhp\JwsToken;
use SecureTokenPhp\JwsHeader;
use SecureTokenPhp\Crypto;
use SecureTokenPhp\Payload;
use SecureTokenPhp\Exceptions\InvalidHeaderException;

final class JwsTest extends TestCase
{
    private const CLAIM_A_NAME = "claimA";
    private const CLAIM_A_VALUE = "A";
    private const CLAIM_B_NAME = "claimB";
    private const CLAIM_B_VALUE = "B";
    private const HS256KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const ES256PRIVKEY  = <<<EOT
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEICS6iE2smBe5dW5P++n6P2d8Dq7/XBj5yhbFlmB71sIioAoGCCqGSM49
    AwEHoUQDQgAErC+7iJTm8kK/NtYdgHYVm9KQwkyp1Z8XGNdB7j+nyTg96usUjM28
    zX6IIetOfIjwY7rZ66VhIy4/YrdVYT/lFA==
    -----END EC PRIVATE KEY-----
    EOT;
    private const ES256PRIVKEY_INVALID  = <<<EOT
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEICS6iE2smBe5dW5P++n6P2d8Dq7/XBj5yhbFlmB71sIioAoGCCqGSM49
    AwEHoUQDQgAErC+7iJTm8kK/NtYdgHYVm9KQwkyp1Z8XGNdB7j+nyTg96usUjM28
    zX6IIetOfIjwY7rZ66VhIy4/YrdVYT/lFA==
    -----END EC PRIVATE KEY-----
    EOT;
    private const ES256PUBKEY = <<<EOT
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErC+7iJTm8kK/NtYdgHYVm9KQwkyp
    1Z8XGNdB7j+nyTg96usUjM28zX6IIetOfIjwY7rZ66VhIy4/YrdVYT/lFA==
    -----END PUBLIC KEY-----
    EOT;
    private const ES256PUBKEY_INVALID = <<<EOT
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErC+7iJTm8kK/NtYdgHYVm9KQwkyp
    1Z8XGNdB7j+nyTg96usUjM28zX6IIetOfIjwY7rZ66VhIy4/YrdVYT/lFA==
    -----END PUBLIC KEY-----
    EOT;

    private const UNSECURED_ENCODED_TOKEN = "eyJhbGciOiJub25lIn0.eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9";
    private const UNSECURED_ENCODED_TOKEN_INVALID_HEADER = "eyJhbGci%%Jub25lIn0.eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9";

    private const HS256_ENCODED_TOKEN = "eyJhbGciOiJIUzI1NiJ9." .
        "eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9." .
        "j1Je21pzqp1e2JBiFjWkB4pGz_rEJw6KrCORSJcez7A";
    private const HS256_ENCODED_TOKEN_INVALID_SIG = "eyJhbGciOiJIUzI1NiJ9." .
        "eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9." .
        "j1Je21pzqp1e2JBiFjWkB4pGz_rEJw6KYCFRSJcez7A";
    private const ES256_ENCODED_TOKEN = "eyJhbGciOiJFUzI1NiJ9." .
        "eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9." .
        "MEYCIQDUhyCTdxWL-yqDRarsXTlaQccGHbymUlJBuEiWCVI0TgIhAIla9avwExREMt6mPVVn-Pi7_-vpFgE1F4tnYF32jCat";
    private const ES256_ENCODED_TOKEN_INVALID_SIG = "eyJhbGciOiJFUzI1NiJ9." .
        "eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9." .
        "MEYCIQDUhyCTdxWL-yqDRarsXTlaQccGHbymUlJBuEHWCVI7TgIhAIla9avwExREMt6mPVVn-Pi7_-vpFgE1F4tnYF32jCat";


    /**
     * @test
     * test unsecured jwt token creation and validation
     */
    public function unsecuredJwtTokenCreateAndValidate()
    {
        $payload = new Payload();
        $payload->setClaim(claimName: self::CLAIM_A_NAME, claimValue: self::CLAIM_A_VALUE);
        $payload->setClaim(claimName: self::CLAIM_B_NAME, claimValue: self::CLAIM_B_VALUE);
        $header = new JwsHeader();
        $header->setAlgorithm(JwsAlgorithmEnum::none);
        $token = new JwsToken(header: $header, payload: $payload);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertTrue(Crypto::validate(token: $token));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals($token->getClaim(self::CLAIM_B_NAME), self::CLAIM_B_VALUE, 'Claim B should match.');
    }


    /**
     * @test
     * Test unsecured JWT token deserialization and validation
     */
    public function unsecuredJwtTokenDeserializationAndValidate()
    {

        $token = JwsToken::fromEncoded(self::UNSECURED_ENCODED_TOKEN);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertTrue(Crypto::validate(token: $token));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals($token->getClaim(self::CLAIM_B_NAME), self::CLAIM_B_VALUE, 'Claim B should match.');
    }

    /**
     * @test
     * Test unsecured JWT token creation and validation
     */
    public function unsecuredJwtTokenDeserializationWithInvalidHeader()
    {
        $this->expectException(InvalidHeaderException::class);
        JwsToken::fromEncoded(self::UNSECURED_ENCODED_TOKEN_INVALID_HEADER);
    }

    /**
     * @test
     * Test HS256 JWT token creation and validation
     */
    public function hmacSha256JwsTokenCreateAndValidate()
    {

        $payload = new Payload();
        $payload->setClaim(claimName: self::CLAIM_A_NAME, claimValue: self::CLAIM_A_VALUE);
        $payload->setClaim(claimName: self::CLAIM_B_NAME, claimValue: self::CLAIM_B_VALUE);

        $header = new JwsHeader();
        $header->setAlgorithm(JwsAlgorithmEnum::HS256);

        $token = new JwsToken(header: $header, payload: $payload);
        $this->assertInstanceOf(Token::class, $token);

        //TODO need a set public / set private and / set key
        $token->setSymmetricalKey(self::HS256KEY);
        $token->signToken();

        $this->assertTrue(Crypto::validate(token: $token));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals($token->getClaim(self::CLAIM_B_NAME), self::CLAIM_B_VALUE, 'Claim B should match.');
    }

    /**
     * @test
     * Test HS256 JWT invalid signature is correctly identified
     */
    public function hmacSha256CorrectlyIdentifysMismatchedSignature()
    {

        $token = JwsToken::fromEncoded(self::HS256_ENCODED_TOKEN_INVALID_SIG, symmetricKey: self::HS256KEY);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertFalse(Crypto::validate(token: $token));
    }

    public function hmacSha256JwsTokenDeserializationAndValidate()
    {
        $token = JwsToken::fromEncoded(self::HS256_ENCODED_TOKEN, symmetricKey: self::HS256KEY);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertTrue(Crypto::validate(token: $token));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals($token->getClaim(self::CLAIM_B_NAME), self::CLAIM_B_VALUE, 'Claim B should match.');
    }

    /**
     * @test
     * test ES256 token an be created and validated
     */
    public function elipticCurveSha256JwsTokenCreateAndValidate()
    {
        $payload = new Payload();
        $payload->setClaim(claimName: self::CLAIM_A_NAME, claimValue: self::CLAIM_A_VALUE);
        $payload->setClaim(claimName: self::CLAIM_B_NAME, claimValue: self::CLAIM_B_VALUE);

        $header = new JwsHeader();
        $header->setAlgorithm(JwsAlgorithmEnum::ES256);
        $token = new JwsToken(header: $header, payload: $payload);
        $token->setPrivateKey(self::ES256PRIVKEY);
        $token->setPublicKey(self::ES256PUBKEY);
        $token->signToken();
        $this->assertInstanceOf(Token::class, $token);
        $this->assertTrue(Crypto::validate(token: $token));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals($token->getClaim(self::CLAIM_B_NAME), self::CLAIM_B_VALUE, 'Claim B should match.');
    }

    /**
     * @test
     * test ES256 can be deserialized and validated
     */
    public function elipticCurveSha256JwsTokenDeserializationAndValidate()
    {
        $token = JwsToken::fromEncoded(
            self::ES256_ENCODED_TOKEN,
            privateKey: self::ES256PRIVKEY,
            publicKey: self::ES256PUBKEY
        );

        $this->assertInstanceOf(Token::class, $token);
        $this->assertTrue(Crypto::validate(token: $token));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals($token->getClaim(self::CLAIM_B_NAME), self::CLAIM_B_VALUE, 'Claim B should match.');
    }

    /**
     * @test
     * Test ES256 token with invalid signature is identified correctly
     */
    public function elipticCurveSha256CorrectlyIdentifysMismatchedSignature()
    {
        $token = JwsToken::fromEncoded(
            self::ES256_ENCODED_TOKEN_INVALID_SIG,
            privateKey: self::ES256PRIVKEY,
            publicKey: self::ES256PUBKEY
        );
        $this->assertInstanceOf(Token::class, $token);
        $this->assertFalse(Crypto::validate(token: $token));
    }
}
