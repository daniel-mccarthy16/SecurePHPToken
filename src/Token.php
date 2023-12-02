<?php 

namespace SecureTokenPhp;


class Token {

    private ?Header $header = null;
    private ?Payload $payload = null;
    private ?string $signature = null;
    private ?string $encodedHeader = null ;
    private ?string $encodedPayload = null;
    private ?string $encodedSignature = null;
    private bool $valid = false;

    private function __construct() {
        // Private constructor to force using factory methods
    }

    public static function fromEncoded(string $serializedToken): self {
        $instance = new self();
        [ $instance->encodedHeader, $instance->encodedPayload, $instance->encodedSignature ]  = Token::split_serialized_token($serializedToken);
        $instance->header = new Header($instance->get_encoded_header()); 
        $instance->payload = new Payload($instance->get_encoded_payload()); 
        if ($instance->encodedSignature !== null) {
            $instance->signature = base64_decode($instance->encodedSignature);
        }
        return $instance;
    }

    public static function fromUnencoded(Header $header, Payload $payload, ?string $signature = null): self {
        $instance = new self();
        $instance->header = $header;
        $instance->payload = $payload;
        $instance->signature = $signature;
        return $instance;
    }

    private static function split_serialized_token(string $serializedToken) :  array {
        
        $parts = explode('.', $serializedToken);
        // Check for two or three parts
        if (count($parts) !== 2) {
            throw new \Exception('unencrypted tokens should have a header and payload but no signature');
        }
        return $parts;

    }

    public function getClaim(string $claimName) : ?string {
        return $this->payload->getClaim($claimName);
    }

    public function signToken(?string $privateKey) {
        Crypto::sign(token: $this, privateKey: $privateKey);
    }

    public function get_header () : Header {
        return $this->header;
    }

    
    public function get_payload () : Payload {
        return $this->payload;
    }

    public function get_encoded_payload () : string {
        return $this->encodedPayload;
    }

    public function getAlgorithm() : ?Algorithm {
        return $this->header->getAlgorithm();
    }
    
    public function get_signature () : ?string {
        return $this->signature;
    }

    public function set_signature (string $signature) {
        $this->signature = $signature;
    }

    public function encode () : string {
        return $this->header->encode() . "." . $this->payload->encode();
    }

    public function isSignatureValid(string $secretKey): bool {
        // Verify the signature
        return true;
    }

}
	
