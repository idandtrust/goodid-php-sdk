<?php

namespace GoodID\Helpers\Response;

use Jose\Factory\JWSFactory;
use Jose\Object\JWK;

class UserinfoVerifierTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid sub
     */
    public function itThrowsWhenSubDoesNotMatchIdToken()
    {
        $idToken = JWSFactory::createJWS(['sub' => 'some sub', 'email_hash' => 'anything', 'uih' => 'd4lLwzkYq_RzXzjEGch1UcEV62S6bwmdVTlBxcNC8u0']);

        $userinfo = JWSFactory::createJWS(['sub' => 'invalid']);
        $userinfo = $userinfo->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES256']);

        $cut = new UserinfoVerifier($idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Unverified userinfo
     */
    public function itThrowsWhenUserinfoHashIsInvalid()
    {
        $idToken = JWSFactory::createJWS(['sub' => 'some sub', 'email_hash' => 'anything', 'uih' => 'invalid']);

        $userinfo = JWSFactory::createJWS(['sub' => 'some sub']);
        $userinfo = $userinfo->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES256']);

        $cut = new UserinfoVerifier($idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     */
    public function itVerifiesUserinfoWithNoEmail()
    {
        $idToken = JWSFactory::createJWS(['sub' => 'some sub', 'email_hash' => 'anything', 'uih' => '-76UsiJWYkXtmjaj9hvDoa5x9_6aM4UStO6vX_rPOLU']);

        $userinfo = JWSFactory::createJWS(['sub' => 'some sub']);
        $userinfo = $userinfo->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES256']);

        $cut = new UserinfoVerifier($idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Unverified email
     */
    public function itThrowsWhenEmailHashIsInvalid()
    {
        $idToken = JWSFactory::createJWS(['sub' => 'some sub', 'email_hash' => 'invalid', 'uih' => 'YpzyyK86ei6ZPf5VFEENUJfcZPSKbCfQN0Kb7nFfmUc']);

        $userinfo = JWSFactory::createJWS(['sub' => 'some sub', 'email' => 'email@example.com']);
        $userinfo = $userinfo->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES256']);

        $cut = new UserinfoVerifier($idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     */
    public function itVerifiesUserinfoWithEmail()
    {
        $idToken = JWSFactory::createJWS(['sub' => 'some sub', 'email_hash' => 'KlOdZSAma1bDsMUlueYSiFi67Mte6baUopBuEjyNbdM', 'uih' => 'YpzyyK86ei6ZPf5VFEENUJfcZPSKbCfQN0Kb7nFfmUc']);

        $userinfo = JWSFactory::createJWS(['sub' => 'some sub', 'email' => 'email@example.com']);
        $userinfo = $userinfo->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES256']);

        $cut = new UserinfoVerifier($idToken);
        $cut->verifyUserinfo($userinfo);
    }
}