<?php

namespace GoodID\Helpers\ClaimChecker;

use GoodID\Helpers\Response\AppSignatureChecklist;
use Jose\Factory\JWSFactory;

class GoodIDAppUserCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @dataProvider acrWithUserProvider
     */
    public function itThrowsWhenUserClaimIsMissingForAcr3AndAbove($acr)
    {
        $jwt = JWSFactory::createJWS(['acr' => $acr]);

        $cut = new GoodIDAppUserChecker(new AppSignatureChecklist());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing user');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unverifiable user
     */
    public function itThrowsWhenUserSignatureIsNotVerified()
    {
        $jwt = JWSFactory::createJWS(['acr' => '3', 'user' => 'some user']);

        $cut = new GoodIDAppUserChecker(new AppSignatureChecklist());

        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @dataProvider acrWithoutUserProvider
     */
    public function itAcceptsMissingSealForAcrsBelow3($acr)
    {
        $jwt = JWSFactory::createJWS(['acr' => $acr]);

        $cut = new GoodIDAppUserChecker(new AppSignatureChecklist());

        $checkedClaims = $cut->checkClaim($jwt);
        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     */
    public function itAcceptsMissingUserIfAcrIsMissing()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new GoodIDAppUserChecker(new AppSignatureChecklist());

        $checkedClaims = $cut->checkClaim($jwt);
        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     * @dataProvider acrWithoutUserProvider
     */
    public function itThrowsWhenUserIsPresentForAcrsBelow3($acr)
    {
        $jwt = JWSFactory::createJWS(['acr' => $acr, 'user' => 'user']);

        $cut = new GoodIDAppUserChecker(new AppSignatureChecklist());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unverifiable user');
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unverifiable user
     */
    public function itThrowsWhenUserIsPresentAndAcrIsMissing()
    {
        $jwt = JWSFactory::createJWS(['user' => 'some user']);

        $cut = new GoodIDAppUserChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itChecksIfUserSignatureIsVerified()
    {
        $jwt = JWSFactory::createJWS(['acr' => '4', 'user' => 'some user']);

        $sigChecklist = $this->createMock(AppSignatureChecklist::class);
        $sigChecklist->expects($this->once())
            ->method('isClaimSigned')
            ->with('user')
            ->willReturn(true);

        $cut = new GoodIDAppUserChecker($sigChecklist);
        $checkedClaims = $cut->checkClaim($jwt);

        $this->assertEquals(['user'], $checkedClaims);
    }

    public static function acrWithUserProvider()
    {
        return [
            ['3'],
            ['4'],
        ];
    }

    public static function acrWithoutUserProvider()
    {
        return [
            ['1'],
            ['2'],
        ];
    }
}
