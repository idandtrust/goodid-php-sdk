<?php

namespace GoodID\Helpers\ClaimChecker;

use GoodID\Helpers\Response\AppSignatureChecklist;
use Jose\Factory\JWSFactory;

class GoodIDAppSealCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing seal
     */
    public function itThrowsWhenAcrIs4AndSealIsMissing()
    {
        $jwt = JWSFactory::createJWS(['acr' => '4']);

        $cut = new GoodIDAppSealChecker(new AppSignatureChecklist());

        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unverifiable seal
     */
    public function itThrowsWhenSealSignatureIsNotVerified()
    {
        $jwt = JWSFactory::createJWS(['acr' => '4', 'seal' => 'some seal']);

        $cut = new GoodIDAppSealChecker(new AppSignatureChecklist());

        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @dataProvider acrWithoutSealProvider
     */
    public function itAcceptsMissingSealForAcrsBelow4($acr)
    {
        $jwt = JWSFactory::createJWS(['acr' => $acr]);

        $cut = new GoodIDAppSealChecker(new AppSignatureChecklist());

        $checkedClaims = $cut->checkClaim($jwt);
        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     */
    public function itAcceptsMissingSealIfAcrIsMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new GoodIDAppSealChecker(new AppSignatureChecklist());

        $checkedClaims = $cut->checkClaim($jwt);
        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     * @dataProvider acrWithoutSealProvider
     */
    public function itThrowsWhenSealIsPresentForAcrsBelow4($acr)
    {
        $jwt = JWSFactory::createJWS(['acr' => $acr, 'seal' => 'some seal']);

        $cut = new GoodIDAppSealChecker(new AppSignatureChecklist());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unverifiable seal');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unverifiable seal
     */
    public function itThrowsWhenSealIsPresentAndAcrIsMissing()
    {
        $jwt = JWSFactory::createJWS(['seal' => 'some seal']);

        $cut = new GoodIDAppSealChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itChecksIfSealSignatureIsVerified()
    {
        $jwt = JWSFactory::createJWS(['acr' => '4', 'seal' => 'some seal']);

        $sigChecklist = $this->createMock(AppSignatureChecklist::class);
        $sigChecklist->expects($this->once())
            ->method('isClaimSigned')
            ->with('seal')
            ->willReturn(true);

        $cut = new GoodIDAppSealChecker($sigChecklist);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['seal'], $checkedClaims);
    }

    public static function acrWithoutSealProvider()
    {
        return [
            ['1'],
            ['2'],
            ['3'],
        ];
    }
}