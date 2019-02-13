<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class GoodIDEmailHashCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing email_hash
     */
    public function itThrowsWhenEmailHashIsMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new GoodIDEmailHashChecker();
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itVerifiesEmailHashPresent()
    {
        $jwt = JWSFactory::createJWS(['email_hash' => 'some email hash']);

        $cut = new GoodIDEmailHashChecker();
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['email_hash'], $checkedClaims);
    }
}