<?php

namespace SecureTokenPhp\Tests;

use PHPUnit\Framework\TestCase;
use SecureTokenPhp\Payload;

final class PayloadTest extends TestCase
{
    /**
     * @test
     * test setter and getter for setting the JWT "subject"
     */
    public function testSetAndGetSubject()
    {
        $payload = new Payload();
        $subject = 'testSubject';
        $payload->setSubject($subject);
        $this->assertEquals($subject, $payload->getSubject());
    }

    /**
     * @test
     * test JWT "subject" returns null when value doesnt exist
     */
    public function testGetSubjectReturnsNullIfNotSet()
    {
        $jwt = new payload();
        $this->assertNull($jwt->getSubject());
    }

    /**
     * @test
     * test setter and getter for setting the JWT "issuer"
     */
    public function testSetAndGetIssuer()
    {
        $payload = new Payload();
        $issuer = 'testIssuer';
        $payload->setIssuer($issuer);
        $this->assertEquals($issuer, $payload->getIssuer());
    }

    /**
     * @test
     * test JWT "issuer" returns null when value doesnt exist
     */
    public function testGetIssuerReturnsNullIfNotSet()
    {
        $jwt = new payload();
        // Test that getIss returns null if no issject is set
        $this->assertNull($jwt->getIssuer());
    }

    /**
     * @test
     * test JWT "Audience" setters and getters
     */
    public function testSetAndGetAudience()
    {
        $jwt = new Payload();
        $audience = 'testAudience';
        $jwt->setAudience($audience);
        $this->assertEquals($audience, $jwt->getAudience());
    }

    /**
     * @test
     * test JWT "Expiration" setters and getters
     */
    public function testSetAndGetExpiration()
    {
        $jwt = new Payload();
        $expTime = time() + 3600; // 1 hour from now
        $jwt->setExpiration($expTime);
        $this->assertEquals($expTime, $jwt->getExpiration());
    }

    /**
     * @test
     * test JWT "NotBefore" setters and getters
     */
    public function testSetAndGetNotBefore()
    {
        $jwt = new Payload();
        $nbfTime = time() + 3600; // 1 hour from now
        $jwt->setNotBefore($nbfTime);
        $this->assertEquals($nbfTime, $jwt->getNotBefore());
    }

    /**
     * @test
     * test JWT "IssuedAt" setters and getters
     */
    public function testSetAndGetIssuedAt()
    {
        $jwt = new Payload();
        $iatTime = time();
        $jwt->setIssuedAt($iatTime);
        $this->assertEquals($iatTime, $jwt->getIssuedAt());
    }

    /**
     * @test
     * test JWT "Jwt ID" setters and getters
     */
    public function testSetAndGetJwtId()
    {
        $jwt = new Payload();
        $jti = 'unique-jwt-id';
        $jwt->setJwtId($jti);
        $this->assertEquals($jti, $jwt->getJwdId());
    }

    /**
     * @test
     * test JWT unregistered claim setters and getters
     */
    public function testSetAndGetCustomClaim()
    {
        $jwt = new Payload();
        $claimName = 'customClaim';
        $claimValue = 'customValue';
        $jwt->setClaim($claimName, $claimValue);
        $this->assertEquals($claimValue, $jwt->getClaim($claimName));
    }
}
