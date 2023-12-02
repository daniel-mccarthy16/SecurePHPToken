<?php

namespace SecureTokenPhp;

class Payload {

    private $claims = [];
    
    public static function fromEncoded(string $encodedPayload): self {
        $instance = new self();
        $instance->claims = base64_decode(json_decode($encodedPayload));
        return $instance;
    }

     /**
     * The "iss" (issuer) claim identifies the principal that issued the JWT.
     * @param string $iss the issuer of the jwt.
     */
    public function setIss(string $iss) {
        $this->claims[registeredclaim::iss->value] = $iss;
    }

    /**
     * 
     * @return string|null the issuer of the jwt.
     */
    public function getIss(): ?string {
        return $this->claims[registeredclaim::iss->value] ?? null;
    }

     /**
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
     * @param string $sub the sub of the jwt.
     */
    public function setSub(string $sub) {
        $this->claims[registeredclaim::sub->value] = $sub;
    }

    /**
     * get the sub (sub) claim.
     * 
     * @return string|null the sub of the jwt.
     */
    public function getSub(): ?string {
        return $this->claims[registeredclaim::sub->value] ?? null;
    }

     /**
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for. 
     * @param string $aud the aud of the jwt.
     */
    public function setAud(string $aud) {
        $this->claims[registeredclaim::aud->value] = $aud;
    }

    /**
     * get the aud (aud) claim.
     * 
     * @return string|null the aud of the jwt.
     */
    public function getAud(): ?string {
        return $this->claims[registeredclaim::aud->value] ?? null;
    }

     /**
     *  The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
     * 
     * @param string $exp the exp of the jwt.
     */
    public function setExp(string $exp) {
        $this->claims[registeredclaim::exp->value] = $exp;
    }

    /**
     * get the exp (exp) claim.
     * 
     * @return string|null the exp of the jwt.
     */
    public function getExp(): ?string {
        return $this->claims[registeredclaim::exp->value] ?? null;
    }

     /**
     * The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processinget the nbf
     * 
     * @param string $nbfg the exp of the jwt.
     */
    public function setNbf(string $exp) {
        $this->claims[registeredclaim::nbf->value] = $exp;
    }

    /**
     * get the nbf (exp) claim.
     * 
     * @return string|null the nbfg of the jwt.
     */
    public function getNbf(): ?string {
        return $this->claims[registeredclaim::nbf->value] ?? null;
    }


     /**
     * set the iat
     * 
     * @param string $iatg the exp of the jwt.
     */
    public function setIat(string $exp) {
        $this->claims[registeredclaim::iat->value] = $exp;
    }

    /**
     * get the iatg (exp) claim.
     * 
     * @return string|null the iatg of the jwt.
     */
    public function getiat(): ?string {
        return $this->claims[registeredclaim::iat->value] ?? null;
    }


     /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * @param string $jti the exp of the jwt.
     */
    public function setJti(string $exp) {
        $this->claims[registeredclaim::jti->value] = $exp;
    }

    /**
     * get the jti (exp) claim.
     * 
     * @return string|null the jtig of the jwt.
     */
    public function getJti(): ?string {
        return $this->claims[registeredclaim::jti->value] ?? null;
    }

    /**
     * set a claim that is not defined as registered in by RFC7519
     * 
     * @return string
     */
    public function setClaim(string $claimName, string $claimValue ) {
        $this->claims[$claimName] = $claimValue;
    }

    /**
     * get the jti (exp) claim.
     * 
     * @return string|null the jtig of the jwt.
     */
    public function getClaim(string $claimName): ?string {
        return $this->claims[$claimName] ?? null;
    }

    // convert the headers to an array
    public function encode(): string {
        return base64_encode(json_encode($this->claims));
    }

}


enum RegisteredClaim : string {
    case iss = "iss";
    case sub = "sub";
    case exp = "exp";
    case nbf = "nbf";
    case iat = "iat";
    case jti = "jti";
    case aud = "aud";
}
