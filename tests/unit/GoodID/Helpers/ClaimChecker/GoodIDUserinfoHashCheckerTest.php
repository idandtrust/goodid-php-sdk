<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class GoodIDUserinfoHashCheckerTest extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        $this->markTestIncomplete();
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unverified userinfo
     */
    public function itThrowsWhenUserinfoHashInIdTokenIsInvalid()
    {
        $idToken = JWSFactory::createJWS(['uih' => 'invalid hash']);
        $userinfo = JWSFactory::createJWS([]);

        $cut = new GoodIDUserinfoHashChecker($idToken);
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     */
    public function itVerifiesHashInIdTokenMatchesUserinfoHash()
    {
        $idToken = JWSFactory::createJWS(['uih' => 'RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o']);
        $userinfo = JWSFactory::createJWS([]);

        $cut = new GoodIDUserinfoHashChecker($idToken);
        $checkedClaims = $cut->checkClaim($userinfo);

        $this->assertEquals([], $checkedClaims);
    }
}