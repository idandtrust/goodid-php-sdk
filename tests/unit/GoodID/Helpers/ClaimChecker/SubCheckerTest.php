<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class SubCheckerTest extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        $this->markTestIncomplete();
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing sub
     */
    public function itThrowsWhenSubIsMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new SubChecker();
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid sub
     */
    public function itThrowsWhenSubIsInvalid()
    {
        $jwt = JWSFactory::createJWS(['sub' => 'invalid']);

        $cut = new SubChecker('expected');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itVerifiesSubPresence()
    {
        $jwt = JWSFactory::createJWS(['sub' => 'anything']);

        $cut = new SubChecker();
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['sub'], $checkedClaims);
    }

    /**
     * @test
     */
    public function itVerifiesSubValue()
    {
        $jwt = JWSFactory::createJWS(['sub' => 'expected']);

        $cut = new SubChecker('expected');
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['sub'], $checkedClaims);
    }
}
