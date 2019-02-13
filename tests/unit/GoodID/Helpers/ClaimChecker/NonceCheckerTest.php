<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class NonceCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid nonce
     */
    public function itThrowsWhenNonceIsExpectedButMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new NonceChecker('some expected nonce');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid nonce
     */
    public function itThrowsWhenNonceIsNotExpectedAndPresent()
    {
        $jwt = JWSFactory::createJWS(['nonce' => 'unexpected nonce']);

        $cut = new NonceChecker(null);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid nonce
     */
    public function itThrowsWhenNonceIsInvalid()
    {
        $jwt = JWSFactory::createJWS(['nonce' => 'invalid nonce']);

        $cut = new NonceChecker('expected nonce');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itVerifiesNonce()
    {
        $jwt = JWSFactory::createJWS(['nonce' => 'expected nonce']);

        $cut = new NonceChecker('expected nonce');
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['nonce'], $checkedClaims);
    }

    /**
     * @test
     */
    public function itAllowsMissingNonceIfNoneIsExpected()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new NonceChecker(null);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals([], $checkedClaims);
    }
}