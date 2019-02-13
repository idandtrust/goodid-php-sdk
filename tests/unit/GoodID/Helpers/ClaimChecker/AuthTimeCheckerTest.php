<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class AuthTimeCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing auth_time
     */
    public function itThrowsWhenAuthTimeIsMissingAndRequestHasMaxAge()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new AuthTimeChecker(0, 30, false);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing auth_time
     */
    public function itThrowsWhenAuthTimeIsMissingAndAuthTimeWasRequested()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new AuthTimeChecker(0, null, true);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage in the future
     */
    public function itThrowsWhenAuthTimeIsInFuture()
    {
        $jwt = JWSFactory::createJWS(['auth_time' => time() + 1]);

        $cut = new AuthTimeChecker(0, 30, true);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itAcceptsAuthTimeInFutureWithinTolerance()
    {
        $tolerance = 10;
        $jwt = JWSFactory::createJWS(['auth_time' => time() + $tolerance]);

        $cut = new AuthTimeChecker($tolerance, 30, true);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['auth_time'], $checkedClaims);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage non-negative
     */
    public function itThrowsIfToleranceIsNegative()
    {
        new AuthTimeChecker(-1, null, false);
    }

    /**
     * @test
     */
    public function itAcceptsMissingAuthTimeWhenNotMaxAgeRequestAndAuthTimeWasNotRequested()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new AuthTimeChecker(0, null, false);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The user was authenticated too long ago
     */
    public function itThrowsWhenAuthTimeIsBeforeMaxAge()
    {
        $jwt = JWSFactory::createJWS(['auth_time' => time() - 60]);

        $cut = new AuthTimeChecker(0, 30, false);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     */
    public function itAcceptsAuthTimeWhenMaxAgeIsNull()
    {
        $jwt = JWSFactory::createJWS(['auth_time' => time() - 30]);

        $cut = new AuthTimeChecker(0, null, false);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['auth_time'], $checkedClaims);
    }
}