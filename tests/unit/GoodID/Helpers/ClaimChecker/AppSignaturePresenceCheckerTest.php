<?php

namespace GoodID\Helpers\ClaimChecker;

use GoodID\Helpers\SecurityLevel;
use Jose\Factory\JWSFactory;

class AppSignaturePresenceCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCanBeCreated() {
        $cut = new AppSignaturePresenceChecker();
        $this->assertTrue($cut instanceof AppSignaturePresenceChecker);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing app signatures
     */
    public function itThrowsWhenSecurityLevelIsHighAndSignaturesAreMissing() {
        $idToken = JWSFactory::createJWS([]);
        $cut = new AppSignaturePresenceChecker(SecurityLevel::HIGH);
        $cut->checkClaim($idToken);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Malformed app signatures
     */
    public function itThrowsWhenSignaturesIsMalformed1() {
        $idToken = JWSFactory::createJWS([
            'signatures' => 'malformed signatures'
        ]);

        $cut = new AppSignaturePresenceChecker(SecurityLevel::HIGH);
        $cut->checkClaim($idToken);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Malformed app signatures
     */
    public function itThrowsWhenSignaturesIsMalformed2() {
        $idToken = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'some signature header',
                    'signature' => 'some signature'
                ],
                'malformed signature',
                [
                    'protected' => 'some signature header',
                    'signature' => 'some signature',
                    'erroneous' => 'extra value'
                ]
            ]
        ]);

        $cut = new AppSignaturePresenceChecker(SecurityLevel::HIGH);
        $cut->checkClaim($idToken);
    }

    /**
     * @test
     */
    public function itChecksSignatureStructure() {
        $idToken = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'user signature header',
                    'signature' => 'user signature'
                ],
                [
                    'protected' => 'device signature header',
                    'signature' => 'device signature',
                ]
            ]
        ]);

        $cut = new AppSignaturePresenceChecker(SecurityLevel::HIGH);
        $this->assertEquals(['signatures'], $cut->checkClaim($idToken));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unexpected app signatures
     */
    public function itThrowsWhenSecurityLevelIsNormalAndAppSignaturesArePresent() {
        $idToken = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'user signature header',
                    'signature' => 'user signature'
                ],
                [
                    'protected' => 'device signature header',
                    'signature' => 'device signature',
                ]
            ]
        ]);

        $cut = new AppSignaturePresenceChecker(SecurityLevel::NORMAL);
        $cut->checkClaim($idToken);
    }

    /**
     * @test
     */
    public function itDoesNotCheckSignaturesWhenSecurityLevelIsNormal() {
        $idToken = JWSFactory::createJWS([]);

        $cut = new AppSignaturePresenceChecker(SecurityLevel::NORMAL);
        $this->assertEquals([], $cut->checkClaim($idToken));
    }
}