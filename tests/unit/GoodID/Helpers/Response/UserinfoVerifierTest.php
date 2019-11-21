<?php

namespace GoodID\Helpers\Response;

use GoodID\Helpers\SecurityLevel;
use Jose\Factory\JWSFactory;
use Jose\Object\JWK;

class UserinfoVerifierTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid sub
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenSubDoesNotMatchIdToken($securityLevel)
    {
        $idToken = $this->createToken([
            'sub' => 'some sub',
            'email_hash' => 'anything',
            'uih' => 'd4lLwzkYq_RzXzjEGch1UcEV62S6bwmdVTlBxcNC8u0'
        ]);

        $userinfo = $this->createToken(['sub' => 'invalid']);

        $cut = new UserinfoVerifier($securityLevel, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Unverified userinfo
     * @dataProvider provideSecurityLevel
     */
    public function itThrowsWhenUserinfoHashIsInvalid($securityLevel)
    {
        $idToken = $this->createToken(['sub' => 'some sub', 'email_hash' => 'anything', 'uih' => 'invalid']);
        $userinfo = $this->createToken(['sub' => 'some sub']);

        $cut = new UserinfoVerifier($securityLevel, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing protected claim
     */
    public function itThrowsWhenSecurityLevelIsHighAndUserOrSealAreMissing()
    {
        $idToken = $this->createToken([
            'sub' => 'some sub',
            'email_hash' => 'anything',
            'uih' => '-76UsiJWYkXtmjaj9hvDoa5x9_6aM4UStO6vX_rPOLU'
        ]);
        $userinfo = $this->createToken(['sub' => 'some sub']);

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Unexpected protected claim
     */
    public function itThrowsWhenSecurityLevelIsNormalAndUserOrSealArePresent()
    {
        $idToken = $this->createToken([
            'sub' => 'some sub',
            'email_hash' => 'anything',
            'uih' => 'cdeAqUxyyV8FqYQ2qIPW0VcfTPZHTwulcnZ-rDSFfY4',
        ]);
        $userinfo = $this->createToken(['sub' => 'some sub', 'user' => 'anything', 'seal' => 'anything']);

        $cut = new UserinfoVerifier(SecurityLevel::NORMAL, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Unverifiable protected claim
     */
    public function itThrowsWhenUserOrSealKeysAreMissing()
    {
        $idToken = $this->createToken([
            'sub' => 'some sub',
            'email_hash' => 'anything',
            'uih' => 'SpOXTPvpkmh4TYdmKHe1KJxof6NTWFce5ZcNVfFN6ZA'
        ]);
        $userinfo = $this->createToken(['sub' => 'some sub', 'user' => 'some user', 'seal' => 'some seal']);

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Malformed protection key
     */
    public function itThrowsWhenUserOrSealKeysAreMalformed1()
    {
        $idToken = $this->createToken([
            'sub' => 'some sub',
            'email_hash' => 'anything',
            'uih' => '67u--W0PFV_4hFu_yN6x7nsApTaZtzEOEt2d7nt134Q'
        ]);
        $userinfo = $this->createToken([
            'sub' => 'some sub',
            'user' => 'some user',
            'seal' => 'some seal',
            'user_jwk' => 'malformed',
            'seal_jwk' => 'malformed',
        ]);

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Malformed protection key
     */
    public function itThrowsWhenUserOrSealKeysAreMalformed2()
    {
        $idToken = $this->createToken([
            'sub' => 'some sub',
            'email_hash' => 'anything',
            'uih' => 'G4yLwidaUBPP0zaHA42BZihPdah89SNyKeQxb0QRDjo'
        ]);
        $userinfo = $this->createToken([
            'sub' => 'some sub',
            'user' => 'some user',
            'seal' => 'some seal',
            'user_jwk' => [],
            'seal_jwk' => [],
        ]);

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \Goodid\Exception\ValidationException
     * @expectedExceptionMessage Invalid signature for claim: user
     */
    public function itThrowsWhenUserSignatureIsInvalid()
    {
        $idToken = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "uih": "jlHBLeHDdhtvwsbhqYx9A8PeiDPx0DB_91t1BEM9EoQ",
                "signatures": [
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InVzZXJfandrIn0",
                        "signature": "invalid signature"
                    },
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InNlYWxfandrIn0",
                        "signature": "h77KObX_KKCHWitLCZauPoTAg4H8p0e1pSfOydRGfCHD42Q0OT3XLRHuPfZKJ_KX9qK22oIBP18XqHPYyh8OAA"
                    }
                ]
            }
        ');
        $userinfo = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "user": "FDRrlYBvSNX9iJQHS9z-HE6YmSt69Bj1Uxyep9F0Xio",
                "seal": "qqcPXf6MmyCprsOgVr4FWkaM6Cvrrvyf8wbIcGOlhnE",
                "user_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I",
                    "y": "BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o"
                },
                "seal_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "00bikdkVy3LdopQkpHcxJqb_vGAUPHm1tdY1FvOEWfY",
                    "y": "vNhs6Y5iuVljAGfydFxqN_gYfbFTPv2EiqwqzgFsAN0"
                }
            }
        ');

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \Goodid\Exception\ValidationException
     * @expectedExceptionMessage Invalid signature for claim: seal
     */
    public function itThrowsWhenSealSignatureIsInvalid()
    {
        $idToken = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "uih": "jlHBLeHDdhtvwsbhqYx9A8PeiDPx0DB_91t1BEM9EoQ",
                "signatures": [
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InVzZXJfandrIn0",
                        "signature": "UNch2isBHk-RCv5ZZYr4m6bqUxHDgA1hvcJ8muIq0FxRN1rZfv24CwWD1Vpn0R6YlHZD7DgVWEabUcRl_Q8bKA"
                    },
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InNlYWxfandrIn0",
                        "signature": "invalid signature"
                    }
                ]
            }
        ');
        $userinfo = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "user": "FDRrlYBvSNX9iJQHS9z-HE6YmSt69Bj1Uxyep9F0Xio",
                "seal": "qqcPXf6MmyCprsOgVr4FWkaM6Cvrrvyf8wbIcGOlhnE",
                "user_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I",
                    "y": "BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o"
                },
                "seal_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "00bikdkVy3LdopQkpHcxJqb_vGAUPHm1tdY1FvOEWfY",
                    "y": "vNhs6Y5iuVljAGfydFxqN_gYfbFTPv2EiqwqzgFsAN0"
                }
            }
        ');

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \Goodid\Exception\ValidationException
     * @expectedExceptionMessage Invalid signature for claim: user
     */
    public function itUsesCorrectKeysForSignatureChecks()
    {
        $idToken = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "uih": "jlHBLeHDdhtvwsbhqYx9A8PeiDPx0DB_91t1BEM9EoQ",
                "signatures": [
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InVzZXJfandrIn0",
                        "signature": "h77KObX_KKCHWitLCZauPoTAg4H8p0e1pSfOydRGfCHD42Q0OT3XLRHuPfZKJ_KX9qK22oIBP18XqHPYyh8OAA"
                    },
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InNlYWxfandrIn0",
                        "signature": "UNch2isBHk-RCv5ZZYr4m6bqUxHDgA1hvcJ8muIq0FxRN1rZfv24CwWD1Vpn0R6YlHZD7DgVWEabUcRl_Q8bKA"
                    }
                ]
            }
        ');
        $userinfo = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "user": "FDRrlYBvSNX9iJQHS9z-HE6YmSt69Bj1Uxyep9F0Xio",
                "seal": "qqcPXf6MmyCprsOgVr4FWkaM6Cvrrvyf8wbIcGOlhnE",
                "user_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I",
                    "y": "BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o"
                },
                "seal_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "00bikdkVy3LdopQkpHcxJqb_vGAUPHm1tdY1FvOEWfY",
                    "y": "vNhs6Y5iuVljAGfydFxqN_gYfbFTPv2EiqwqzgFsAN0"
                }
            }
        ');

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @expectedException \Goodid\Exception\ValidationException
     * @expectedExceptionMessage Protection key thumbprint mismatch
     */
    public function itThrowsWhenKeyThumbprintsAreInvalid()
    {
        $idToken = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "uih": "B7aY-ig8iXG284pfPLy-lsLpQheO3trycrpqnEoOtwY",
                "signatures": [
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InVzZXJfandrIn0",
                        "signature": "UNch2isBHk-RCv5ZZYr4m6bqUxHDgA1hvcJ8muIq0FxRN1rZfv24CwWD1Vpn0R6YlHZD7DgVWEabUcRl_Q8bKA"
                    },
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InNlYWxfandrIn0",
                        "signature": "h77KObX_KKCHWitLCZauPoTAg4H8p0e1pSfOydRGfCHD42Q0OT3XLRHuPfZKJ_KX9qK22oIBP18XqHPYyh8OAA"
                    }
                ]
            }
        ');
        $userinfo = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "user": "invalid user",
                "seal": "invalid seal",
                "user_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I",
                    "y": "BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o"
                },
                "seal_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "00bikdkVy3LdopQkpHcxJqb_vGAUPHm1tdY1FvOEWfY",
                    "y": "vNhs6Y5iuVljAGfydFxqN_gYfbFTPv2EiqwqzgFsAN0"
                }
            }
        ');

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @doesNotPerformAssertions
     *
     * @throws \GoodID\Exception\ValidationException
     */
    public function itVerifiesUserinfoWithHighSecurityLevel()
    {
        $idToken = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "uih": "jlHBLeHDdhtvwsbhqYx9A8PeiDPx0DB_91t1BEM9EoQ",
                "signatures": [
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InVzZXJfandrIn0",
                        "signature": "UNch2isBHk-RCv5ZZYr4m6bqUxHDgA1hvcJ8muIq0FxRN1rZfv24CwWD1Vpn0R6YlHZD7DgVWEabUcRl_Q8bKA"
                    },
                    {
                        "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InNlYWxfandrIn0",
                        "signature": "h77KObX_KKCHWitLCZauPoTAg4H8p0e1pSfOydRGfCHD42Q0OT3XLRHuPfZKJ_KX9qK22oIBP18XqHPYyh8OAA"
                    }
                ]
            }
        ');
        $userinfo = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "user": "FDRrlYBvSNX9iJQHS9z-HE6YmSt69Bj1Uxyep9F0Xio",
                "seal": "qqcPXf6MmyCprsOgVr4FWkaM6Cvrrvyf8wbIcGOlhnE",
                "user_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "PU7gBcfvoMjmqIXXtqoXOdgcbnX7B8ImUJcZGDTMO2I",
                    "y": "BYAjw9igtymTwKzxVPp4VpPE0Zw3HZaBmrgEGdhVI5o"
                },
                "seal_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "00bikdkVy3LdopQkpHcxJqb_vGAUPHm1tdY1FvOEWfY",
                    "y": "vNhs6Y5iuVljAGfydFxqN_gYfbFTPv2EiqwqzgFsAN0"
                }
            }
        ');

        $cut = new UserinfoVerifier(SecurityLevel::HIGH, $idToken);
        $cut->verifyUserinfo($userinfo);
    }

    /**
     * @test
     * @doesNotPerformAssertions
     *
     * @throws \GoodID\Exception\ValidationException
     */
    public function itVerifiesUserinfoWithNormalSecurityLevel()
    {
        $idToken = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk",
                "uih": "AUVosO1VPWttDgEzhPj_P371Gq1ttC4TkpGN69GDJc8"
            }
        ');
        $userinfo = $this->createToken('
            {
                "sub": "w5lM2D941-0z3WZXr5DUiOk9ihO8jxFAXSEzFeJsMlk"
            }
        ');

        $cut = new UserinfoVerifier(SecurityLevel::NORMAL, $idToken);
        $cut->verifyUserinfo($userinfo);
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

    /**
     * @param string|array $payload
     *
     * @return \Jose\Object\JWSInterface
     */
    private function createToken($payload)
    {
        if (is_string($payload)) {
            $payload = json_decode($payload, true);
        }
        $token = JWSFactory::createJWS($payload);
        $token = $token->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES256']);
        return $token;
    }
}