<?php

namespace GoodID\Helpers\ClaimChecker;

use Jose\Factory\JWSFactory;

class GoodIDAcrCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @dataProvider goodAcrProvider
     */
    public function itValidatesAcr($goodAcr)
    {
        $cut = new GoodIDAcrChecker();

        $jwt = JWSFactory::createJWS(['acr' => $goodAcr]);
        $checkedClaims = $cut->checkClaim($jwt);
        $this->assertEquals(['acr'], $checkedClaims);
    }

    /**
     * @test
     */
    public function itAcceptsMissingAcr()
    {
        $cut = new GoodIDAcrChecker();

        $jwt = JWSFactory::createJWS([]);
        $checkedClaims = $cut->checkClaim($jwt);
        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid acr
     */
    public function itThrowsForInvalidAcr()
    {
        $cut = new GoodIDAcrChecker();

        $jwt = JWSFactory::createJWS(['acr' => 'invalid acr']);
        $cut->checkClaim($jwt);
    }

    public static function goodAcrProvider()
    {
        return [
            ['1'],
            ['2'],
            ['3'],
            ['4'],
        ];
    }
}