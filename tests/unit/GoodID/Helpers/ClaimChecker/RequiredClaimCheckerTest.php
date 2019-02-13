<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class RequiredClaimCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @dataProvider requiredClaimProvider
     */
    public function itThrowsWhenRequiredClaimIsMissing($claimName)
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new RequiredClaimChecker($claimName);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageRegExp('/Missing.*' . $claimName . '/');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @dataProvider requiredClaimProvider
     */
    public function itThrowsWhenRequiredClaimValueIsInvalid($claimName, $claimValue)
    {
        $jwt = JWSFactory::createJWS([$claimName => 'invalid']);

        $cut = new RequiredClaimChecker($claimName, $claimValue);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageRegExp('/Invalid.*' . $claimName . '.*expected.*' . $claimValue . '/');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itVerifiesPresenceOfRequiredClaims()
    {
        $jwt = JWSFactory::createJWS(['some claim' => 'some value']);

        $cut = new RequiredClaimChecker('some claim');
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['some claim'], $checkedClaims);
    }

    /**
     * @test
     */
    public function itVerifiesClaimValue()
    {
        $jwt = JWSFactory::createJWS(['some claim' => 'some value']);

        $cut = new RequiredClaimChecker('some claim', 'some value');
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['some claim'], $checkedClaims);
    }

    public static function requiredClaimProvider()
    {
        return [
            ['claim1', 'value1'],
            ['claim2', 'value2'],
            ['claim3', 'value3'],
        ];
    }
}