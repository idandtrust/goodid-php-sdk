<?php

namespace GoodID\Helpers\Response;

use GoodID\Helpers\SecurityLevel;
use Jose\Factory\JWSFactory;
use Jose\Object\JWK;

class IdTokenVerifierTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing issuer
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenIssuerIsMissing($securityLevel)
    {
        $idToken = $this->buildIdToken([
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid issuer
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenIssuerIsInvalid($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'invalid issuer'
        ]);

        $cut = new IdTokenVerifier('valid issuer', 'some audience', $securityLevel, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing sub
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenSubjectIsMissing($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer'
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing audience
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenAudienceIsMissing($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid audience
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenAudienceIsInvalid($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'invalid audience',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'valid audience', $securityLevel, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing expiration
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenExpirationIsMissing($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The token has expired
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenTokenIsExpired($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() - 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing auth_time
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenAuthTimeIsMissingAndMaxAgeRequest($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, 30, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing auth_time
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenAuthTimeIsMissingAndAuthTimeWasRequested($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, true, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The user was authenticated in the future
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenAuthTimeIsInTheFuture($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'auth_time' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, true, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid nonce
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenRequestedNonceIsMissing($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, false,
            'some nonce value');
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid nonce
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenNonceIsPresentWithoutBeingRequested($securityLevel)
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'nonce' => 'some nonce value'
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', $securityLevel, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing app signatures
     */
    public function itThrowsWhenSecurityLevelIsHighAndSignaturesAreMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'uih' => 'userinfo hash',
            'acr' => '3',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', SecurityLevel::HIGH, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Unexpected app signatures
     */
    public function itThrowsWhenSecurityLevelIsNormalAndSignaturesArePresent()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'uih' => 'userinfo hash',
            'acr' => '2',
            'signatures' => [],
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', SecurityLevel::NORMAL, null, false, null);
        $cut->verifyIdToken($idToken);
    }

    private function buildIdToken(array $claims)
    {
        $jws = JWSFactory::createJWS($claims);
        $jws = $jws->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES256']);
        return $jws;
    }

    /**
     * @return array
     */
    public function provideSecurityLevel()
    {
        return [
            'security level normal' => [SecurityLevel::NORMAL],
            'security level high' => [SecurityLevel::HIGH],
        ];
    }
}