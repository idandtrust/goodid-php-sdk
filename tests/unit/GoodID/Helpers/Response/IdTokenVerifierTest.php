<?php

namespace GoodID\Helpers\Response;

use Jose\Factory\JWSFactory;
use Jose\Object\JWK;

class IdTokenVerifierTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing issuer
     */
    public function itThrowsWhenIssuerIsMissing()
    {
        $idToken = $this->buildIdToken([
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid issuer
     */
    public function itThrowsWhenIssuerIsInvalid()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'invalid issuer'
        ]);

        $cut = new IdTokenVerifier('valid issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing sub
     */
    public function itThrowsWhenSubjectIsMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer'
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing audience
     */
    public function itThrowsWhenAudienceIsMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid audience
     */
    public function itThrowsWhenAudienceIsInvalid()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'invalid audience',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'valid audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing expiration
     */
    public function itThrowsWhenExpirationIsMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The token has expired
     */
    public function itThrowsWhenTokenIsExpired()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() - 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing auth_time
     */
    public function itThrowsWhenAuthTimeIsMissingAndMaxAgeRequest()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', 30, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing auth_time
     */
    public function itThrowsWhenAuthTimeIsMissingAndAuthTimeWasRequested()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, true, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The user was authenticated in the future
     */
    public function itThrowsWhenAuthTimeIsInTheFuture()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'auth_time' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, true, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid nonce
     */
    public function itThrowsWhenRequestedNonceIsMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, 'some nonce value');
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid nonce
     */
    public function itThrowsWhenNonceIsPresentWithoutBeingRequested()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'nonce' => 'some nonce value'
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid acr
     */
    public function itThrowsWhenAcrIsPresentAndInvalid()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'acr' => 'invalid',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing email_hash
     */
    public function itThrowsWhenEmailHashIsMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing claim `uih`
     */
    public function itThrowsWhenUserinfoHashIsMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'email_hash' => 'some email hash',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing user
     */
    public function itThrowsWhenAcrIs3AndUserIsMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'email_hash' => 'some email hash',
            'uih' => 'userinfo hash',
            'acr' => '3',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Unverifiable user
     */
    public function itThrowsWhenUserSignatureIsMissing()
    {
        $idToken = $this->buildIdToken([
            'iss' => 'some issuer',
            'sub' => 'some sub',
            'aud' => 'some audience',
            'exp' => time() + 1000,
            'email_hash' => 'some email hash',
            'uih' => 'userinfo hash',
            'acr' => '3',
            'user' => 'some user',
        ]);

        $cut = new IdTokenVerifier('some issuer', 'some audience', null, false, null);
        $cut->verifyIdToken($idToken);
    }

    private function buildIdToken(array $claims)
    {
        $jws = JWSFactory::createJWS($claims);
        $jws = $jws->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES256']);
        return $jws;
    }
}