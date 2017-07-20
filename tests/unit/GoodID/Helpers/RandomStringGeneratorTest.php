<?php

namespace GoodID\Helpers;

class RandomStringGeneratorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itGeneratesCorrectLength()
    {
        $value = RandomStringGenerator::getPseudoRandomString(10);
        $this->assertEquals(10, strlen($value));

        $value = RandomStringGenerator::getPseudoRandomString(5);
        $this->assertEquals(5, strlen($value));
    }

    /**
     * @test
     */
    public function itAllowsDifferentKeyspaces()
    {
        $value = RandomStringGenerator::getPseudoRandomString(20, 'ab');
        $this->assertFalse((bool)preg_match('/[^ab]/', $value));
        $value = RandomStringGenerator::getPseudoRandomString(20, '01');
        $this->assertFalse((bool)preg_match('/[^01]/', $value));
    }

    /**
     * @test
     */
    public function itReturnsDifferentValues()
    {
        $value1 = RandomStringGenerator::getPseudoRandomString(10);
        $value2 = RandomStringGenerator::getPseudoRandomString(10);

        $this->assertNotEquals($value1, $value2);
    }
}
