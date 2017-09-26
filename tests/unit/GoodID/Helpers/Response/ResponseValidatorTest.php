<?php

namespace GoodID\Helpers\Response;

use GoodID\Helpers\Claim;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\StateNonceHandler;

class ResponseValidatorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @dataProvider claimProvider
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The idToken and userinfo data belong to different users.
     */
    public function itComparesTokenSubjectWithUserinfoSubject($idToken, $userinfo)
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator(null, $serverConfig, $stateNonceHandler);

        $validator->validateTokensBelongTogether($idToken, $userinfo);
    }

    /**
     * @test
     */
    public function itPassesSubjectValidationIfBothAreEqual()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator(null, $serverConfig, $stateNonceHandler);

        $idToken = [Claim::NAME_SUBJECT => 'subject#1'];
        $userinfo = [Claim::NAME_SUBJECT => 'subject#1'];

        $validator->validateTokensBelongTogether($idToken, $userinfo);
    }

    /**
     * @test
     */
    public function itUsesStateNonceHandlerForStateValidation()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);

        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->expects($this->once())
            ->method('validateState')
            ->with($this->equalTo('any state'))
            ->willReturn(true);

        $validator = new ResponseValidator(null, $serverConfig, $stateNonceHandler);

        $validator->validateState('any state');
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The received state is invalid.
     */
    public function itFailsIfStateValidationFails()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);

        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->expects($this->once())
            ->method('validateState')
            ->willReturn(false);

        $validator = new ResponseValidator(null, $serverConfig, $stateNonceHandler);

        $validator->validateState('wrong state');
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid issuer.
     */
    public function userinfoValidationFailsIfIssuerIsNotOurServer()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->expects($this->once())
            ->method('getIssuerUri')
            ->willReturn('Not my server');

        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator(null, $serverConfig, $stateNonceHandler);

        $validator->validateUserInfo($this->userInfoJws);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid audience.
     */
    public function userinfoValidationFailsIfWeAreNotTheIntendedAudience()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');

        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('not-audience-client-id', $serverConfig, $stateNonceHandler);

        $validator->validateUserInfo($this->userInfoJws);
    }

    /**
     * @test
     */
    public function userinfoValidationReturnsClaims()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');

        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $claims = $validator->validateUserInfo($this->userInfoJws);
        $this->assertTrue(is_array($claims));
        $this->assertEquals('My server', $claims['iss']);
        $this->assertEquals('Your client', $claims['aud']);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Expired token.
     */
    public function idtokenValidationFailsIfExpirationIsMissing()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithoutExpiration,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Expired token.
     */
    public function idtokenValidationFailsIfIdTokenIsExpired()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->expiredIdTokenJws,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Expired token.
     */
    public function idtokenValidationFailsIfExpirationIsTooFarAway()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithExpirationTooFar,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

     /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid issuance time.
     */
    public function idtokenValidationFailsIfIatIsMissing()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithoutIat,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid issuance time.
     */
    public function idtokenValidationFailsIfIatIsInFuture()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithIatInFuture,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The authorization code hash is invalid.
     */
    public function idtokenValidationFailsIfAuthCodeHashIsIncorrect()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);


        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithIncorrectCodeHash,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The authorization code hash is invalid.
     */
    public function idtokenValidationFailsIfAuthCodeHashIsMissing()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithMissingCodeHash,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     */
    public function idtokenValidationSucceedsIfAuthCodeHashIsIncorrectButNonceIsConvenient()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);
        $stateNonceHandler->method('getNonceValidationMode')
            ->willReturn(StateNonceHandler::NONCE_VALIDATION_MODE_CONVENIENT_TOTP);


        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithIncorrectCodeHash,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     */
    public function idtokenValidationSucceedsIfAuthCodeHashIsMissingButNonceIsConvenient()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);
        $stateNonceHandler->method('getNonceValidationMode')
            ->willReturn(StateNonceHandler::NONCE_VALIDATION_MODE_CONVENIENT_TOTP);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithMissingCodeHash,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid issuance time.
     */
    public function idtokenValidationFailsIfIatIsTooEarly()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithTooEarlyIat,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid authentication time.
     */
    public function idtokenValidationFailsIfAuthTimeIsInFuture()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithAuthTimeInFuture,
            'dummy-client-secret',
            $this->serverTime,
            7200,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid authentication time.
     */
    public function idtokenValidationFailsIfAuthTimeIsOlderThanMaxAge()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWith7200SecondsOldAuthTime,
            'dummy-client-secret',
            $this->serverTime,
            7199,
            'some-auth-code'
        );
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid authentication time.
     */
    public function idtokenValidationFailsIfAuthTimeIsMissingAndMaxAgeIsSet()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');

        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJwsWithAuthTimeMissing,
            'dummy-client-secret',
            $this->serverTime,
            7200,
            'some-auth-code'
        );
    }


    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The received nonce is invalid.
     */
    public function idtokenValidationFailsWithInvalidNonce()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(false);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $validator->validateIdToken(
            $this->idTokenJws,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );
    }

    /**
     * @test
     */
    public function idtokenValidationReturnsDataWithoutMaxAge()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $idToken = $validator->validateIdToken(
            $this->idTokenJws,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );

        $this->assertTrue(is_array($idToken));
        $this->assertArrayHasKey('iss', $idToken);
    }

    /**
     * @test
     */
    public function idtokenValidationReturnsDataWithMaxAge()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $idToken = $validator->validateIdToken(
            $this->idTokenJwsWith7200SecondsOldAuthTime,
            'dummy-client-secret',
            $this->serverTime,
            7200,
            'some-auth-code'
        );

        $this->assertTrue(is_array($idToken));
        $this->assertArrayHasKey('iss', $idToken);
    }

    /**
     * @test
     */
    public function idtokenValidationRemovesClaims()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $idToken = $validator->validateIdToken(
            $this->idTokenJwsWithClaims,
            'dummy-client-secret',
            $this->serverTime,
            null,
            'some-auth-code'
        );

        $this->assertTrue(is_array($idToken));
        $this->assertArrayNotHasKey('claims', $idToken);
    }

    /**
     * @test
     */
    public function itValidatesUserinfoGivenRequestedClaims()
    {
        $this->markTestIncomplete('TODO: Needs example data; validation rules are unclear');
    }

    public function claimProvider()
    {
        return [
            'missing subjects' => [
                [],
                [],
            ],
            'subject missing from userinfo' => [
                [Claim::NAME_SUBJECT => 'Subject#1'],
                [],
            ],
            'subject missing from idToken' => [
                [],
                [Claim::NAME_SUBJECT => 'Subject#2'],
            ],
            'different subjects' => [
                [Claim::NAME_SUBJECT => 'Subject#1'],
                [Claim::NAME_SUBJECT => 'Subject#2'],
            ]
        ];
    }

    private $userInfoJws = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IlEzLUd1andlLUlaUFJpM3hnYkw0MFNIRUdkNXUyUk1CVDQzcmFMdmJ3Y1EiLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiMEpJci05YWlBdDVYS2hUVERPTExDWG9nd2JtVmJ4bHZwNzhjcFJfTlY4TSIsInkiOiJCMnpObGs2eWJmUDB4eldIQnVDZXp0TEZpMEROTWdUTlJCY3h3LWhLVGhVIiwiYWxnIjoiRVMyNTYifSwiY2xhaW1zIjpbXX0.Q8e-7S15e3KmTHgbE8GDov54ifw4EJwIiZIgtbVY9A7HL5-TIVnb00mRhrWH8QjJf--nFc-aI3gcIlReKVqTjQ';

    private $serverTime = 1499872383;
    private $idTokenJwsWithoutExpiration = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IkVrRE1zWnI4Tk9qNDdtNk9XZkJMSkk0amMtT0p4SGpQaWE2MHhRLVltRVUiLCJpYXQiOjE0OTk4NzIzODMsImF1dGhfdGltZSI6MTQ5OTg3MjM4MywibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiY3hmck85WkFlTVdsbk9SSlFUUG5FcjNOOTV0RVNzQ0JNcHY2TUNyN196YyIsInkiOiJYUnpBWDMwNnRpNnB6RUtxdlR4cXZUYjZaMTdMMXVRa3ZjNVpJWmFuUEVNIiwiYWxnIjoiRVMyNTYifSwibm9uY2UiOiJub25jZSB2YWx1ZSIsImNfaGFzaCI6ImtZS19EOElXQVpnWFJhNmVQR0liM3cifQ.d_uWofUo00wid2BePqzgxLVaRIb9BTcZw0ajuN2tuVaaPN7naYASd6TA9uZDRlSeZW0mYNWribSTbKTRN08XLA';
    private $expiredIdTokenJws = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6ImFoQlRudmwzM0x6M3JRT3pqck1KWU05NUhFNWExQ0JWbkVIdkF1ZkJ6bXciLCJleHAiOjE0OTk4NzIzODIsImlhdCI6MTQ5OTg3MjM4MywiYXV0aF90aW1lIjoxNDk5ODcyMzgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiJwd21JWmFHZ1VjWi1sM1ByQkI2dTdWNXFNclJrYWVTcW1NbmljOU82UHVvIiwieSI6IjRIVkVGcHE2SkJ1QXAyUExnZ0ZyYmZwbUozNDlSVTBRdU5UbWVXaVhadlkiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoia1lLX0Q4SVdBWmdYUmE2ZVBHSWIzdyJ9.6uXdfHL_FQrJcbJnna3V9tln_9aqkFiq2jieQ4D39cB60ApVMJtVtYumQakzsRY5MBUoa80m9wZc41PGozjhkQ';
    private $idTokenJwsWithExpirationTooFar = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6Indaa2NULWlKQTNfMnZsNWRLNnY4SEdrb19sbUstVEVrMExDTzNFaUZScE0iLCJleHAiOjE1MDUxNDYzODMsImlhdCI6MTQ5OTg3MjM4MywiYXV0aF90aW1lIjoxNDk5ODcyMzgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiIzdFpaSm1nTXVBQTVjVGFSVEhRRm40S1pvTUhiSV85enRWWURfUTlqS1VzIiwieSI6IkMzdkd2TllQR3NPSlBvbE45c2JfczRJdFg1ekFoV09yMnFaWUpjQl96TXMiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoia1lLX0Q4SVdBWmdYUmE2ZVBHSWIzdyJ9.9TPQCOHyYeUXSJ_hOzON_Kuhj_9124KvOovzaLs3pwiNzAydaZmvxar1HsTx926tXlVCSXYsKzmSry_tuyvkYw';
    private $idTokenJwsWithoutIat = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6ImwybE9rMnFsekExckdFbXlOdlcxck1LOGx4azQ4T3E2bnZFS1A2aXdUTUkiLCJleHAiOjE0OTk4NzU5ODMsImF1dGhfdGltZSI6MTQ5OTg3MjM4MywibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiNVprVWJUUUMzVXE1Smw0YllPd3BFWW1mTElna1ZHU0ZhSDJnUnNERG9lSSIsInkiOiJjVWtvQWFzOXFGOTlUaW5DTXQ0R0xGZng0Z01OY3IwRmx3cWFqSmM0TkQ4IiwiYWxnIjoiRVMyNTYifSwibm9uY2UiOiJub25jZSB2YWx1ZSIsImNfaGFzaCI6ImtZS19EOElXQVpnWFJhNmVQR0liM3cifQ.L53JXAoLJeowajW3oghp_We8bz6KYfSAtK-LWCjaeCr8_KVoC2PYbFPobNOt2HjBBWDhkctKPRvDTITmy8Ek-Q';
    private $idTokenJwsWithIatInFuture = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6Imk5UWFJRUgxeFFKenlkdnlMMU9sRkpRdzJxa1R1ajNyd1VlUWpXak9yakUiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4NCwiYXV0aF90aW1lIjoxNDk5ODcyMzgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiJUUzVIMTBBcWVUQlRVTjkyc2k1Q3VwQ3lVNFNySV83Z0lKeThYYnY0M1RVIiwieSI6Ik1pQS13SHJsOVNDektBdk9DeFFhSE9GNEQwcjVjQVQ2dnlzamd6OHdDQ1UiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoia1lLX0Q4SVdBWmdYUmE2ZVBHSWIzdyJ9.mfCFDnvVnAKLrGlEAqQqUuht2sdMnroswYq_vASZ7OyF25Zcl6T6l2KJgMhBAqyk-sMeJ8rK788NgfPkDYNM0A';
    private $idTokenJwsWithTooEarlyIat = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IkQyUERGcnhiOVZFR2s2WTUzVHNqVGdackdwSFNJbC0zbG1hN2NSRVItWVUiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5NDYwMTk4MywiYXV0aF90aW1lIjoxNDk5ODcyMzgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiJoTHpsRkEyZVBYNEtOWlZ2OENfWExpdjcxVXpadEIwb01xelNiLUsxWElVIiwieSI6IkJXUHNDSkZyc1NUZjZ2eGZ2Qk5MYTNoRTFXS3UwdTMtQ2UwZlJLZTNKTTQiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoia1lLX0Q4SVdBWmdYUmE2ZVBHSWIzdyJ9.j8NtBkkIBnkANl0sb6PwSvPoCNoz6A-0kEXcEGu8IINN_5HDYevk9rwq0pBOR6pczrsMQvljIaNozgyQ2Uh8Xw';
    private $idTokenJwsWithAuthTimeInFuture = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6InVrNndScURzc1I4MnR4MmxQUjRsUVkzZzdDNTNuYUdWZXhJN19qSVZuNmsiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywiYXV0aF90aW1lIjoxNDk5ODcyMzg0LCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiJ6VHFjQ3FLcnI5SU1sZ2JnOFppLWtZODIzRzZvemJPSFRMOFVtZzRxYi1NIiwieSI6Ikl2UzNHN3BsdU5VZU1iWjBqTFd5SjBYNzItLXJQQmprUjM0RmZFWVUtRVEiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoia1lLX0Q4SVdBWmdYUmE2ZVBHSWIzdyJ9.qrO70owCL7IsHK_vRtO-_SqB-5nlNVj3wxQDHH2pOsfmB8Oe49ov3Xwu5NL3kpIJqHCmp4k6ic7s6sqnK-BYww';
    private $idTokenJwsWith7200SecondsOldAuthTime = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IlNsOGQxMy1ZNzRGbXlXZXRkTVdXZU1yaWdNbUFTT2ZGMmRDbWdRdU1jTEUiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywiYXV0aF90aW1lIjoxNDk5ODY1MTgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiJ5dHd1S3d4dENIVHllQXgtYW1ETXZDUEJ6YjlneEZZRnpTWjE3dG5Qb2JRIiwieSI6InRaTHVyTUtESmRwYUJkdlI1ZkN2cFBzM3NEM2I1LW9xVkd0eXFGd1Zfa3MiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoia1lLX0Q4SVdBWmdYUmE2ZVBHSWIzdyJ9.yqji0RaSfjmpJGz5cMVV3C4sey7-SseDlJub1hw7C3s_rhtHe2JYOyzkY8WjXlMnQmVlqoe1HQGi4AVQ-912pA';
    private $idTokenJws = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IkptaXhxQ1ZOdXdYeW1na196aFM2Z0dIWFJjTlpmYno0Z0tXamdHVmQ1ZjAiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywiYXV0aF90aW1lIjoxNDk5ODcyMzgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiIyZUNGQ2ZHRGh1SE9vX0Etc0NDVWltVktwQnZMb3VjenpWYURQMUdhdUZBIiwieSI6IlVwaXMwR1dCWXpXNE9DaHJueldVUTJ0OG1nemVuc2YxU2dUUG5odWtBdDAiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoia1lLX0Q4SVdBWmdYUmE2ZVBHSWIzdyJ9.BYwpFiJF4nLCDuDmCHr4ftxQa2T7RSxaGghQZeWteZioQrRM9Q6H2XoBjRTPAAnkkcDtOUHP8j3hrxiQRhl6vg';
    private $idTokenJwsWithAuthTimeMissing = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6Il9QLVRLN2N6eG1tRE5zNW9ZT1FOb25pT0N4Y3VtbmxyazRNNnM3eWFfLVEiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoidkNBTUFtT3ZOVktDUTNBSUg2MC05bzdzeDA2MlJ0YjJPai1BR2xPYWIwZyIsInkiOiJjd3BQOEpEZ09GS3F2SmVPakdxMzdjMlk4dUFXNUQxSFNPNW5EeEZUZDBVIiwiYWxnIjoiRVMyNTYifSwibm9uY2UiOiJub25jZSB2YWx1ZSIsImNfaGFzaCI6ImtZS19EOElXQVpnWFJhNmVQR0liM3cifQ.fkZlayLSv2dCHlerjv5MmMdtDOH3SiM0ZsU3g68nraJzva79vSXYq9gZ064rVJOgf6dKpnc5og105NKwrIcEew';
    private $idTokenJwsWithClaims = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IjRoOG0yaW1mbm1lWUFodERJZXNWUDhiaTdpT1RScjBUX2VnSUZuQllhTDQiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywiYXV0aF90aW1lIjoxNDk5ODcyMzgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiJNa2YxUnZacWxzdHN0bTJLSTlFdDQxc2lFaDlET0wxcXdUT2l6Wk1OQWU0IiwieSI6Im9KTi01d2MxbUhsZWNMdFZzR1dGNEJJWGhFODVRZHJxRm12T2d0WGdZdlUiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoia1lLX0Q4SVdBWmdYUmE2ZVBHSWIzdyIsImNsYWltcyI6eyJlbWFpbCI6ImVtYWlsQGV4YW1wbGUudGxkIn19.F1aHMkf7lCS4t82Eaid7aeniXDJFTuDXmok1h9Kj8Gh_xYC15xiny8RfYF_j9oe8h3k_zxkblWsRjh96f-OoWA';
    private $idTokenJwsWithIncorrectCodeHash = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6InllSVhfckx2Xy12a0RjNEU4T1lHWi1FbC1TYWVHMml5WHJSNmg1QzZZSEkiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywiYXV0aF90aW1lIjoxNDk5ODcyMzgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiJfV1Fkc0FOSHZLYW1uelJRRzFPUVFSc2FWZHlyZFNzNFBZYnJZd29FRzBzIiwieSI6InhHUFZkbFVEb3RyS2UwNzhuN2NTMkZweTZ6WkpOMXc2TG85R1FyR05qRkkiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIiwiY19oYXNoIjoid293LW11Y2gtaW5jb3JyZWN0LXZlcnktZXJyb3IifQ.twh-EBd330QOlQ-NQ3sB6QKnIx19T9e1Sk42kI8Ocb-JpiT9dJ7TGG34TYj_9Esz-FQiFYJJi8o-bgPey4U4Ng';
    private $idTokenJwsWithMissingCodeHash = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6ImI3dWNkOEtFc2lmMXdoUVFQSTdhcG1ybU9Ed2hxZkdzQ09peXJPbmFMWnciLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywiYXV0aF90aW1lIjoxNDk5ODcyMzgzLCJuYmYiOjE0OTk4NzIzODMsInN1Yl9qd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsIngiOiJqOHpPck05N21fcFA2VUxOeE1zVVBzQWIwdUIzRFF5OUxvVVBPQUpMYVhVIiwieSI6Ii11SG5LekFSX2JfQl9sLXhjaGpBdi1XMzQxa2p6ei00MVp4QmsteUU1WTAiLCJhbGciOiJFUzI1NiJ9LCJub25jZSI6Im5vbmNlIHZhbHVlIn0.CN5AOojCW3JaWBQpn454i8iceA9jPeGr5DxpxV0b9_YqV5zVznmJvE34cBrS-pLfpWnn0sWGKAANRQM4GjElCQ';
}
