<?php

namespace GoodID\Helpers\ClaimChecker;

use GoodID\Helpers\SecurityLevel;
use Jose\Factory\JWSFactory;

class AppSignatureCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCanBeCreated()
    {
        $idToken = JWSFactory::createJWS([]);

        $cut = new AppSignatureChecker(SecurityLevel::NORMAL, $idToken, null);
        $this->assertTrue($cut instanceof AppSignatureChecker);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing protected claim
     */
    public function itThrowsWhenSecurityLevelIsHighAndProtectedClaimIsMissing()
    {
        $idToken = JWSFactory::createJWS([]);
        $userinfo = JWSFactory::createJWS([]);

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unverifiable protected claim
     */
    public function itThrowsWhenSecurityLevelIsHighAndProtectedClaimKeyIsMissing()
    {
        $idToken = JWSFactory::createJWS([]);
        $userinfo = JWSFactory::createJWS(['user' => 'anything']);

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Malformed protection key
     */
    public function itThrowsWhenSecurityLevelIsHighAndProtectedClaimKeyIsMalformed1()
    {
        $idToken = JWSFactory::createJWS([]);
        $userinfo = JWSFactory::createJWS(['user' => 'anything', 'user_jwk' => 'malformed']);

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Malformed protection key
     */
    public function itThrowsWhenSecurityLevelIsHighAndProtectedClaimKeyIsMalformed2()
    {
        $idToken = JWSFactory::createJWS([]);
        $userinfo = JWSFactory::createJWS(['user' => 'anything', 'user_jwk' => []]);

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Protection key thumbprint mismatch
     */
    public function itThrowsWhenProtectionKeyThumbprintDoesNotEqualProtectedClaim()
    {
        $idToken = JWSFactory::createJWS([]);
        $userinfo = JWSFactory::createJWS([
            'user' => 'invalid value',
            'user_jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I',
                'y' => 'BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o',
            ]
        ]);

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing app signatures
     */
    public function itThrowsWhenAppSignaturesAreMissing()
    {
        $idToken = JWSFactory::createJWS([]);
        $userinfo = JWSFactory::createJWS([
            'user' => 'FDRrlYBvSNX9iJQHS9z-HE6YmSt69Bj1Uxyep9F0Xio',
            'user_jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I',
                'y' => 'BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o',
            ]
        ]);

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Missing signature for claim
     */
    public function itThrowsWhenAppSignatureIsMissingForClaim()
    {
        $idToken = JWSFactory::createJWS([
            'signatures' => []
        ]);
        $userinfo = JWSFactory::createJWS([
            'user' => 'FDRrlYBvSNX9iJQHS9z-HE6YmSt69Bj1Uxyep9F0Xio',
            'user_jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I',
                'y' => 'BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o',
            ]
        ]);

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid signature for claim
     */
    public function itThrowsWhenSignatureIsInvalid()
    {
        $idToken = JWSFactory::createJWS([
            'signatures' => [
                [
                    'protected' => 'eyJhbGciOiJFUzI1NiIsImtpZCI6InVzZXJfandrIn0',
                    'signature' => 'invalid signature'
                ]
            ]
        ]);
        $userinfo = JWSFactory::createJWS([
            'user' => 'FDRrlYBvSNX9iJQHS9z-HE6YmSt69Bj1Uxyep9F0Xio',
            'user_jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I',
                'y' => 'BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o',
            ]
        ]);

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid signature for claim
     */
    public function itChecksTheCorrectSignature()
    {
        // Id token with good signature for wrong key
        $idToken = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54",
                "signatures": [
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InVzZXJfandrIn0",
                        "signature": "invalid signature"
                    },
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InNlYWxfandrIn0",
                        "signature": "U0YBq6G4gn3_P6KQc7l0jzb-iStjhPvkWLfriU4fDnrzCwkzbV0Ks5bcLj7yeQxdR9IwtrYU8X6DGM4viUn_vQ"
                    }
                ]
            }
        ', true));
        $userinfo = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54",
                "user": "9K_VNLfvMvGzK2RENZICzcxfRYxrC_ge8KqF9RQLJGM",
                "user_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "2Z_jLCn-jF95Xbgcljj8cB4gEGAh9t88JnRKNGBtXx0",
                    "y": "3feS0EPkGM-h5HxsmIdOcNhu9-HDKn3Eg2xD1qOZm-s"
                }
            }
        ', true));

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     */
    public function itChecksSignature()
    {
        $idToken = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54",
                "signatures": [
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InVzZXJfandrIn0",
                        "signature": "U0YBq6G4gn3_P6KQc7l0jzb-iStjhPvkWLfriU4fDnrzCwkzbV0Ks5bcLj7yeQxdR9IwtrYU8X6DGM4viUn_vQ"
                    }
                ]
            }
        ', true));
        $userinfo = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54",
                "user": "9K_VNLfvMvGzK2RENZICzcxfRYxrC_ge8KqF9RQLJGM",
                "user_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "2Z_jLCn-jF95Xbgcljj8cB4gEGAh9t88JnRKNGBtXx0",
                    "y": "3feS0EPkGM-h5HxsmIdOcNhu9-HDKn3Eg2xD1qOZm-s"
                }
            }
        ', true));

        $cut = new AppSignatureChecker(SecurityLevel::HIGH, $idToken, "user");
        $this->assertEquals(['user'], $cut->checkClaim($userinfo));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unexpected protected claim
     */
    public function itThrowsWhenSecurityLevelIsNormalAndProtectedClaimIsPresent()
    {
        $idToken = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54"
            }
        ', true));
        $userinfo = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54",
                "user": "9K_VNLfvMvGzK2RENZICzcxfRYxrC_ge8KqF9RQLJGM"
            }
        ', true));

        $cut = new AppSignatureChecker(SecurityLevel::NORMAL, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unexpected protection key
     */
    public function itThrowsWhenSecurityLevelIsNormalAndAppKeyIsPresent()
    {
        $idToken = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54"
            }
        ', true));
        $userinfo = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54",
                "user_jwk": []
            }
        ', true));

        $cut = new AppSignatureChecker(SecurityLevel::NORMAL, $idToken, "user");
        $cut->checkClaim($userinfo);
    }

    /**
     * @test
     */
    public function itAllowsMissingClaimWhenSecurityLevelIsNormal()
    {
        $idToken = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54"
            }
        ', true));
        $userinfo = JWSFactory::createJWS(json_decode('
            {
                "sub": "DEidbnsO_BXUaf-hNnqgKvTitbKuv5et7ZxUgf3uX54"
            }
        ', true));

        $cut = new AppSignatureChecker(SecurityLevel::NORMAL, $idToken, "user");
        $this->assertEquals([], $cut->checkClaim($userinfo));
    }

}