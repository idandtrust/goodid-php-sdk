<?php

namespace GoodID\Helpers\ClaimChecker;

use GoodID\Helpers\Response\AppSignatureChecklist;
use Jose\Factory\JWSFactory;

class GoodIDAppSignatureCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itAllowsMissingSignatures()
    {
        $jwt = JWSFactory::createJWS([]);

        $cut = new GoodIDAppSignatureChecker(new AppSignatureChecklist());

        $checkedClaims = $cut->checkClaim($jwt);
        $this->assertEquals([], $checkedClaims);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing app signing key
     */
    public function itThrowsWhenSignatureHeaderIsMissing()
    {
        $jwt = JWSFactory::createJWS([
            'signatures' => [
                [
                    'signature' => 'anything'
                ],
            ]
        ]);

        $cut = new GoodIDAppSignatureChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing app signing key
     */
    public function itThrowsWhenSigningKeyIsMissing()
    {
        $jwt = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'e30',
                    'signature' => 'anything'
                ]
            ]
        ]);

        $cut = new GoodIDAppSignatureChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid app signing key
     */
    public function itThrowsWhenSigningKeyKidIsMissing()
    {
        $jwt = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'eyJqd2siOnsia3R5Ijoibm9uZSJ9fQ',
                    'signature' => 'anything'
                ]
            ]
        ]);

        $cut = new GoodIDAppSignatureChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid app signing key
     */
    public function itThrowsWhenSigningKeyKidIsInvalid()
    {
        $jwt = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'eyJqd2siOnsia3R5Ijoibm9uZSIsImtpZCI6Indyb25nLWtpZCJ9fQ',
                    'signature' => 'anything'
                ]
            ]
        ]);

        $cut = new GoodIDAppSignatureChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to verify
     */
    public function itThrowsWhenSignatureIsInvalid()
    {
        $jwt = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImtpZCI6ImR1bW15X2p3ayIsImNydiI6IlAtMjU2IiwieCI6Ik8yMURVUUFWcXdwc2tNazNvQkwzX1Q0c1hIWEE3RmZkOXZfek5ObDZudnciLCJ5IjoidHlIM0VOc1VjOUM4aWZLSWkyUU1fSVAxcFR1NDExZzc4RGRDb3U2bF9sOCJ9fQ',
                    'signature' => 'bad signature'
                ]
            ]
        ]);

        $cut = new GoodIDAppSignatureChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing app signed claim
     */
    public function itThrowsWhenSignedClaimIsMissing()
    {
        $jwt = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImtpZCI6ImR1bW15X2p3ayIsImNydiI6IlAtMjU2IiwieCI6Ik8yMURVUUFWcXdwc2tNazNvQkwzX1Q0c1hIWEE3RmZkOXZfek5ObDZudnciLCJ5IjoidHlIM0VOc1VjOUM4aWZLSWkyUU1fSVAxcFR1NDExZzc4RGRDb3U2bF9sOCJ9fQ',
                    'signature' => '4BLW-6XPk4ddtrrpb9zWCy4qjNOHMDqDg9IlifFh7JZRrJE9oBqECsJmmott_TjZ3n8hJZzQ2QvNPvEGjCAQ3g'
                ]
            ]
        ]);

        $cut = new GoodIDAppSignatureChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad app signature
     */
    public function itThrowsWhenSignedClaimValueIsInvalid()
    {
        $jwt = JWSFactory::createJWS([
            'dummy' => 'invalid',
            'signatures' => [
                [
                    'protected' => 'eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImtpZCI6ImR1bW15X2p3ayIsImNydiI6IlAtMjU2IiwieCI6Ik8yMURVUUFWcXdwc2tNazNvQkwzX1Q0c1hIWEE3RmZkOXZfek5ObDZudnciLCJ5IjoidHlIM0VOc1VjOUM4aWZLSWkyUU1fSVAxcFR1NDExZzc4RGRDb3U2bF9sOCJ9fQ',
                    'signature' => 'M0TgE8-3zeHcyIYqAOZTWnVMVcm5y3U7u_WYTs8yh9x7u7k9qM9JIGUOn5SQmZRWq-lBSAwWLafTM9HYqXyZtw'
                ]
            ]
        ]);

        $cut = new GoodIDAppSignatureChecker(new AppSignatureChecklist());
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itVerifiesAppSignature()
    {
        $jwt = JWSFactory::createJWS([
            'dummy' => 'i_OYK9EZ3Fy1NkS2qFayT2TXDckTDE1blPZCLgNBjDA',
            'signatures' => [
                [
                    'protected' => 'eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImtpZCI6ImR1bW15X2p3ayIsImNydiI6IlAtMjU2IiwieCI6Ik8yMURVUUFWcXdwc2tNazNvQkwzX1Q0c1hIWEE3RmZkOXZfek5ObDZudnciLCJ5IjoidHlIM0VOc1VjOUM4aWZLSWkyUU1fSVAxcFR1NDExZzc4RGRDb3U2bF9sOCJ9fQ',
                    'signature' => 'QiVa0PQIABfXfgTb5rQFbMfMCDaC5DI4BVEofbE5xq_Br7ziAGyPq40C1U3g0UGNCLLbL6TP8mz7c69INMqj8g'
                ]
            ]
        ]);

        $sigChecklist = $this->createMock(AppSignatureChecklist::class);
        $sigChecklist->expects($this->once())
            ->method('markClaimSigned')
            ->with('dummy');

        $cut = new GoodIDAppSignatureChecker($sigChecklist);
        $cut->checkClaim($jwt);
    }

    /**
     * @test
     */
    public function itVerifiesMultipleSignatures()
    {
        $jwt = JWSFactory::createJWS([
            'dummy' => 'i_OYK9EZ3Fy1NkS2qFayT2TXDckTDE1blPZCLgNBjDA',
            'other' => 'lL6XEUS-Bi9Nt4fxK-d99_sKlP8xjoMmTDiK9E6hF40',
            'signatures' => [
                [
                    'protected' => 'eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImtpZCI6ImR1bW15X2p3ayIsImNydiI6IlAtMjU2IiwieCI6Ik8yMURVUUFWcXdwc2tNazNvQkwzX1Q0c1hIWEE3RmZkOXZfek5ObDZudnciLCJ5IjoidHlIM0VOc1VjOUM4aWZLSWkyUU1fSVAxcFR1NDExZzc4RGRDb3U2bF9sOCJ9fQ',
                    'signature' => 'f3bfIx3h3gip0PXRXsjPE98YTj85ImFY2dqkxiCQF0rhmaLC2dTzwSv7I0Q7ujsT-NfVY2pQBEN6NdBDYDOcKA'
                ],
                [
                    'protected' => 'eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImtpZCI6Im90aGVyX2p3ayIsImNydiI6IlAtMjU2IiwieCI6InNyRlpUcW1CNzhreVhVekJCTTFQUVlFNld4QldzVHcyLW91dVVYdkFQWkkiLCJ5IjoiNDdIVWxjUkk0Tklsa3BqZHotd1FRN29FMU9lRmNsMU0wd1ExMHBzcFM1WSJ9fQ',
                    'signature' => '9U-hjUOmPYoFjjV9LJVXA-W23S1Z6mP9cBQDo1Gqp0qIcfmekH8BqgJnVE2A1pA635A7Ir6W5suxEaStdlBL4A'
                ]
            ]
        ]);

        $sigChecklist = $this->createMock(AppSignatureChecklist::class);
        $sigChecklist->expects($this->exactly(2))
            ->method('markClaimSigned')
            ->withConsecutive(
                [$this->equalTo('dummy')],
                [$this->equalTo('other')]
            );

        $cut = new GoodIDAppSignatureChecker($sigChecklist);
        $cut->checkClaim($jwt);
    }
}

/*
 * Keys used:
 *
 * dummy_jwk:
 * { kty: 'EC',
 *   kid: 'dummy_jwk',
 *   crv: 'P-256',
 *   x: 'O21DUQAVqwpskMk3oBL3_T4sXHXA7Ffd9v_zNNl6nvw',
 *   y: 'tyH3ENsUc9C8ifKIi2QM_IP1pTu411g78DdCou6l_l8',
 *   d: 'MbaWxXjd1_sRmdUTkgvY4KC5VbqV9YwmgarWfP1UEGk' }
 *
 * other_jwk:
 * { kty: 'EC',
 *   kid: 'other_jwk',
 *   crv: 'P-256',
 *   x: 'srFZTqmB78kyXUzBBM1PQYE6WxBWsTw2-ouuUXvAPZI',
 *   y: '47HUlcRI4NIlkpjdz-wQQ7oE1OeFcl1M0wQ10pspS5Y',
 *   d: 'IrbRWx-Ni1vfJMZXsmqJJwm39rY1MrvAp0j-0X0l0UA' }
 */