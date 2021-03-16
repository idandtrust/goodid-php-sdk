<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class IssuerCheckerTest extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        $this->markTestIncomplete();
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing issuer
     */
    public function itThrowsWhenIssuerIsMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new IssuerChecker('anything');
        $cut->checkClaim($jwt);


    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid issuer
     */
    public function itThrowsWhenIssuerIsInvalid()
    {
        $jwt = JWSFactory::createJWS(['iss' => 'invalid']);

        $cut = new IssuerChecker('some issuer');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itVerifiesIssuer()
    {
        $jwt = JWSFactory::createJWS(['iss' => 'some issuer']);

        $cut = new IssuerChecker('some issuer');
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['iss'], $checkedClaims);
    }
}