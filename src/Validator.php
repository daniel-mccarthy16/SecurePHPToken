<?php
namespace SecureTokenPhp;

class Validator {

    public function validate(Payload $payload): bool { return true; } 

    public function validateExpiration(Payload $payload): bool { return true; } 

    public function validateIssuedAt(Payload $payload): bool { return true; } 
}
