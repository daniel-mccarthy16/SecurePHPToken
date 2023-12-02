<?php
require_once 'vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use SecureTokenPhp\Algorithm;
use SecureTokenPhp\Token;
use SecureTokenPhp\Crypto;
use SecureTokenPhp\Payload;
use SecureTokenPhp\Header;

final class JWTHandlerIntegrationTest extends TestCase {

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
    private const ES256PUBKEY = <<<EOT
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErC+7iJTm8kK/NtYdgHYVm9KQwkyp
    1Z8XGNdB7j+nyTg96usUjM28zX6IIetOfIjwY7rZ66VhIy4/YrdVYT/lFA==
    -----END PUBLIC KEY-----
    EOT;

    public function test_alg_none_jws_validation() {

        $payload = new Payload();
        $payload->setClaim(claimName: self::CLAIM_A_NAME, claimValue: self::CLAIM_A_VALUE);
        $payload->setClaim(claimName: self::CLAIM_B_NAME, claimValue: self::CLAIM_B_VALUE);

        $header = new Header();
        $header->setAlgorithm(Algorithm::none);

        $token = Token::fromUnencoded(header: $header, payload: $payload);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertTrue(Crypto::validate(token: $token));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals( $token->getClaim(self::CLAIM_B_NAME),self::CLAIM_B_VALUE, 'Claim B should match.');

    }

    public function test_alg_hs256_jws_token_create_and_validate() {

        $payload = new Payload();
        $payload->setClaim(claimName: self::CLAIM_A_NAME, claimValue: self::CLAIM_A_VALUE);
        $payload->setClaim(claimName: self::CLAIM_B_NAME, claimValue: self::CLAIM_B_VALUE);

        $header = new Header();
        $header->setAlgorithm(Algorithm::HS256);

        $token = Token::fromUnencoded(header: $header, payload: $payload);
        $this->assertInstanceOf(Token::class, $token);

        $token->signToken(privateKey: self::HS256KEY);
        $this->assertTrue(Crypto::validate(token: $token, key: self::HS256KEY));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals( $token->getClaim(self::CLAIM_B_NAME),self::CLAIM_B_VALUE, 'Claim B should match.');
    }
    //
    public function testAlgEs256JwsTokenCreateAndValidate() {
        $payload = new Payload();
        $payload->setClaim(claimName: self::CLAIM_A_NAME, claimValue: self::CLAIM_A_VALUE);
        $payload->setClaim(claimName: self::CLAIM_B_NAME, claimValue: self::CLAIM_B_VALUE);

        $header = new Header();
        $header->setAlgorithm(Algorithm::ES256);

        $token = Token::fromUnencoded(header: $header, payload: $payload);
        $token->signToken(privateKey: self::ES256PRIVKEY);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertTrue(Crypto::validate(token: $token, key: self::ES256PUBKEY));
        $this->assertEquals($token->getClaim(self::CLAIM_A_NAME), self::CLAIM_A_VALUE, 'Claim A should match.');
        $this->assertEquals( $token->getClaim(self::CLAIM_B_NAME),self::CLAIM_B_VALUE, 'Claim B should match.');
    }
}
