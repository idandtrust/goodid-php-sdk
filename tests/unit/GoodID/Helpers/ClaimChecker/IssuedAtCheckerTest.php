<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class IssuedAtCheckerTest extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        $this->markTestIncomplete();
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing issued at
     */
    public function itThrowsWhenIssuedAtIsMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new IssuedAtChecker(0);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage in the future
     */
    public function itThrowsWhenIssuedAtIsInFuture()
    {
        $jwt = JWSFactory::createJWS(['iat' => time() + 1]);

        $cut = new IssuedAtChecker(0);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itAcceptsIssuedAtInFutureWithinTolerance()
    {
        $tolerance = 10;
        $jwt = JWSFactory::createJWS(['iat' => time() + $tolerance]);

        $cut = new IssuedAtChecker($tolerance);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['iat'], $checkedClaims);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage non-negative
     */
    public function itThrowsIfToleranceIsNegative()
    {
        new IssuedAtChecker(-1);
    }
}