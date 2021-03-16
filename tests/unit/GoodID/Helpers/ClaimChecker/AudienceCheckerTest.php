<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class AudienceCheckerTest extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        $this->markTestIncomplete();
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing audience
     */
    public function itThrowsWhenAudienceIsMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new AudienceChecker('some audience');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid audience
     */
    public function itThrowsWhenAudienceIsInvalid()
    {
        $jwt = JWSFactory::createJWS(['aud' => 'wrong audience']);

        $cut = new AudienceChecker('some audience');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid audience
     */
    public function itThrowsWhenAudienceDoesNotContainTargetAudience()
    {
        $jwt = JWSFactory::createJWS(['aud' => ['wrong audience']]);

        $cut = new AudienceChecker('some audience');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itValidatesAudience()
    {
        $jwt = JWSFactory::createJWS(['aud' => 'some audience']);

        $cut = new AudienceChecker('some audience');
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['aud'], $checkedClaims);
    }

    /**
     * @test
     */
    public function itValidatesAudienceInArray()
    {
        $jwt = JWSFactory::createJWS(['aud' => ['wrong audience', 'some audience']]);

        $cut = new AudienceChecker('some audience');
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['aud'], $checkedClaims);
    }
}