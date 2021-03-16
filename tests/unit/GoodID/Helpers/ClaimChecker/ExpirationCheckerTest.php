<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class ExpirationCheckerTest extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        $this->markTestIncomplete();
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing expiration
     */
    public function itThrowsWhenExpirationIsMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new ExpirationChecker(0);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage expired
     */
    public function itThrowsWhenJwtIsExpired()
    {
        $jwt = JWSFactory::createJWS(['exp' => time() - 1]);

        $cut = new ExpirationChecker(0);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itAcceptsExpiredTokensWithinTolerance()
    {
        $tolerance = 10;
        $jwt = JWSFactory::createJWS(['exp' => time() - $tolerance]);

        $cut = new ExpirationChecker($tolerance);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['exp'], $checkedClaims);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage non-negative
     */
    public function itThrowsWhenToleranceIsNegative()
    {
        new ExpirationChecker(-1);
    }
}