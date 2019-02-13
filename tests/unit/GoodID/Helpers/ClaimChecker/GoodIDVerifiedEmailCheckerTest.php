<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class GoodIDVerifiedEmailCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itVerifiesMissingEmailHashWhenUserinfoDoesNotContainEmail()
    {
        $idToken = JWSFactory::createJWS(['email_hash' => 'anything']);
        $userinfo = JWSFactory::createJWS([]);

        $cut = new GoodIDVerifiedEmailChecker($idToken);
        $checkedClaims = $cut->checkClaim($userinfo);

        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unverified email
     */
    public function itThrowsWhenUserinfoEmailDoesNotMatchHashInIdToken()
    {
        $idToken = JWSFactory::createJWS(['email_hash' => 'invalid hash']);
        $userinfo = JWSFactory::createJWS(['email' => 'invalid@example.com']);

        $cut = new GoodIDVerifiedEmailChecker($idToken);
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     */
    public function itVerifiesEmailAgainstHashInIdToken()
    {
        $idToken = JWSFactory::createJWS(['email_hash' => 'ETn4RBxALdtXfAqRP81V-9lZkXZdVMJRgzdrElimC1c']);
        $userinfo = JWSFactory::createJWS(['email' => 'valid@example.com']);

        $cut = new GoodIDVerifiedEmailChecker($idToken);
        $checkedClaims = $cut->checkClaim($userinfo);

        $this->assertEquals(['email'], $checkedClaims);
    }
}