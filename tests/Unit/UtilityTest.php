<?php

namespace SecureTokenPhp\Tests;

use PHPUnit\Framework\TestCase;
use SecureTokenPhp\Exceptions\TokenSplitException;
use SecureTokenPhp\Utility;

final class UtilityTest extends TestCase
{
    private const INVALID_SINGLE_SEGMENT_TOKEN = "eyJhbGciOiJIUzI1NiJ9";
    private const INVALID_MUTLI_SEGMENT_TOKEN = "eyJhbGciOiJFUzI1NiJ9." .
        "eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9." .
        "eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9." .
        "MEYCIQDUhyCTdxWL-yqDRarsXTlaQccGHbymUlJBuEiWCVI0TgIhAIla9avwExREMt6mPVVn-Pi7_-vpFgE1F4tnYF32jCat";
    private const HS256_ENCODED_TOKEN = "eyJhbGciOiJIUzI1NiJ9." .
        "eyJjbGFpbUEiOiJBIiwiY2xhaW1CIjoiQiJ9." .
        "j1Je21pzqp1e2JBiFjWkB4pGz_rEJw6KrCORSJcez7A";
    private const TEST_STRING = 'This is a test string.';

    /**
     * @test
     * test token splitter with a single segment
     */
    public function tokenSpliterThrowsExceptionOnSingleSegment()
    {
        $this->expectException(TokenSplitException::class);
        Utility::splitSerializedToken(self::INVALID_SINGLE_SEGMENT_TOKEN);
    }

    /**
     * @test
     * test token splitter with a fourth, invalid segment
     */
    public function tokenSpliterThrowsExceptionWhenTooManySegments()
    {
        $this->expectException(TokenSplitException::class);
        Utility::splitSerializedToken(self::INVALID_MUTLI_SEGMENT_TOKEN);
    }

    /**
     * @test
     * test token splitter with a valid serialized token
     */
    public function tokenSpliterReturnsArrayOfCorrectLength()
    {
        $parts = Utility::splitSerializedToken(self::HS256_ENCODED_TOKEN);
        $this->assertIsArray($parts);
        $this->assertCount(3, $parts, 'The token should have exactly 3 segments');
    }

    /**
     * @test
     * test we can encode a string and successfully reverse the process
     */
    public function testFileSystemSafeBase64EncodeAndReverse()
    {
        $encodedString = Utility::fileSystemSafeBase64(self::TEST_STRING);

        // Check if the encoded string contains no '+' or '/' characters
        $this->assertStringNotContainsString('+', $encodedString);
        $this->assertStringNotContainsString('/', $encodedString);

        // Decode the string and check if it matches the original string
        $decodedString = Utility::decodeFileSystemSafeBase64($encodedString);
        $this->assertEquals(self::TEST_STRING, $decodedString);
    }


    /**
     * @test
     * Test the unqiue ID generator returns 32 hex characters and its not pumping out the same thing everytime
     */
    public function testGenerateUniqueId()
    {
        $uniqueId = Utility::generateUniqueId();

       // Check if the length of the unique ID is 32 characters
        $this->assertEquals(32, strlen($uniqueId));

       // Check if the unique ID is a valid hexadecimal string
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $uniqueId);

       // Generate another ID and check for uniqueness
        $anotherUniqueId = Utility::generateUniqueId();
        $this->assertNotEquals($uniqueId, $anotherUniqueId);
    }
}
