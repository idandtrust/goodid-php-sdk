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
     */
    public function userinfoValidationRemovesEmailCertWhenEmailIsVerified()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');

        $stateNonceHandler = $this->createMock(StateNonceHandler::class);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $claims = $validator->validateUserInfo($this->userInfoJwsWithEmailCert, true)['claims'];
        $this->assertTrue(is_array($claims));
        $this->assertArrayNotHasKey('email_cert', $claims);
        $this->assertArrayHasKey('email_verified', $claims);
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

        $validator->validateIdToken($this->idTokenJwsWithoutExpiration, 'dummy-client-secret', $this->serverTime);
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

        $validator->validateIdToken($this->expiredIdTokenJws, 'dummy-client-secret', $this->serverTime);
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

        $validator->validateIdToken($this->idTokenJwsWithExpirationTooFar, 'dummy-client-secret', $this->serverTime);
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

        $validator->validateIdToken($this->idTokenJwsWithoutIat, 'dummy-client-secret', $this->serverTime);
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

        $validator->validateIdToken($this->idTokenJwsWithIatInFuture, 'dummy-client-secret', $this->serverTime);
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

        $validator->validateIdToken($this->idTokenJwsWithTooEarlyIat, 'dummy-client-secret', $this->serverTime);
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

        $validator->validateIdToken($this->idTokenJws, 'dummy-client-secret', $this->serverTime);
    }

    /**
     * @test
     */
    public function idtokenValidationReturnsData()
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getIssuerUri')
            ->willReturn('My server');
        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->method('validateNonce')
            ->willReturn(true);

        $validator = new ResponseValidator('Your client', $serverConfig, $stateNonceHandler);

        $idToken = $validator->validateIdToken($this->idTokenJws, 'dummy-client-secret', $this->serverTime);
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

        $idToken = $validator->validateIdToken($this->idTokenJwsWithClaims, 'dummy-client-secret', $this->serverTime);
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
    private $userInfoJwsWithEmailCert = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IjBaMXZHX1RBa21uUTV0ZHZCX1lTSl9kSTdXZVYzNmdXamh4TGIzLVZpbG8iLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYXRHeFVhdkFHamZvSUNCS3NVMm5BdWRsOTJZekJGakNXZ3dVa05GRDZkUSIsInkiOiJ2eURzclhJc2NXNEVmMU5neDBxd09zMUt3QndOcjdjYVpIOEZpVUVzWlV3IiwiYWxnIjoiRVMyNTYifSwiY2xhaW1zIjp7ImVtYWlsX3ZlcmlmaWVkIjoidXNlckBleGFtcGxlLnRsZCIsImVtYWlsX2NlcnQiOiJjZXJ0In19.k1MMtOw0n5Y1kFblzHjKc5Uk9IJ1AAwvSUVCWUKF0IziQ0gWpSM_2ve-Mjnflde-UfozhwiBqgmoaQkgxVYJwA';

    private $serverTime = 1499872383;
    private $idTokenJwsWithoutExpiration = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6Il8xQWtpaHpuYVN2YU4zX19pLVk5LS1WX3dnOTlJM3VBNlZoR1pjZjhnNDAiLCJpYXQiOjE0OTk4NzIzODMsIm5iZiI6MTQ5OTg3MjM4Mywic3ViX2p3ayI6eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6IkZqbXJDdlNTS2FrYTl5RUUxSGwzZTBfd1d0SVZEUkMzYklhMFkyNms0NUUiLCJ5IjoiNkg0WklfbXlwLXFQY0FhODVnS0g2SmJyb08zYmV1aUhBLVNuUW9PY04zcyIsImFsZyI6IkVTMjU2In19.WwS5VSOq-e7y3zQSI2Ujrx3mmmfCR3e90yOOYUHX_dBb7LFvuO95hpdoJDFt84jJTsgiqRY1u9DN-WSS_58jjg';
    private $expiredIdTokenJws = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6Il9KUUg3STdiWDYyRUI0T2oxZVpMZVNCZklSR2ppbThmUVVaOE5JZXlmRTAiLCJleHAiOjE0OTk4NzIzODIsImlhdCI6MTQ5OTg3MjM4MywibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVjF1Sk9YZ0REQVVpNnhIVTFPSWFSOGd0ckJIdklacVJmVnpDNUJ3QmNsYyIsInkiOiJWWHpkLTlIcUljTGFIS3ozV1hiRzJod29TUjc1NHpHREFiOU5RWkcwTVBZIiwiYWxnIjoiRVMyNTYifX0.7k8fSbyByipAYDgxMQv0ewHXe5E0VYL1Tez9Vugyy8JKLD8f4g8oqJldEqUr9S7UlP5uKNyGBWGU2BcBucgdgQ';
    private $idTokenJwsWithExpirationTooFar = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6ImlXc3AzeEF4djdla29VaXN1US1TSDYtYjI5ZENDWVREczNOeFB3bF84MFEiLCJleHAiOjE1MDUxNDYzODMsImlhdCI6MTQ5OTg3MjM4MywibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiX2NubmNwNjJMLTFfRkIybTRWQUVRNjd4UWJDTnV4OU0tUU1acndPSFc1byIsInkiOiJOX3VieC1rQ09STGtMZ0Qzay1yWnJMeU1mMEVGZ2NvVHhKYjRqLUx5eHBZIiwiYWxnIjoiRVMyNTYifX0.vUslOdXFtgXRKIQ0GtaNOZYJIFKqCd-2Ad-ih8rfEIGLeAf-pu9tdVsVsSiFpvJy6L5ZLsDXCYveWWKZpdksiw';
    private $idTokenJwsWithoutIat = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IlhuMFZPQVFCTTNrTVZvQXNROHd4NFFwZzhGdDlRYmdRalA4SG5BNFNxYlUiLCJleHAiOjE0OTk4NzU5ODMsIm5iZiI6MTQ5OTg3MjM4Mywic3ViX2p3ayI6eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6ImFJU0JqblZJM2Y4VzBwb0tCaU9nV21YZ1RBMEY0aXRud2w2M2FrQUVITjgiLCJ5IjoiazNlWi1uWm1GOE0wVHk0c3ROMXFfYjk4b1BiNk1uZDVDTFVBSkdjRkFNYyIsImFsZyI6IkVTMjU2In0sIm5vbmNlIjoibm9uY2UgdmFsdWUiLCJjbGFpbXMiOnsiZW1haWwiOiJlbWFpbEBleGFtcGxlLnRsZCJ9fQ.7ecDqLxme5kg-1rUqT7b_ijRVxIm8MjrfmFkqZ3HgNuyY9MDkgEqieDNkjNXT1G8B8SqNGU5lRyvySXRSbTyaA';
    private $idTokenJwsWithIatInFuture = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IkYzS24wRlBvbGh3MnJsQ0FRVjJWSmJuWW40Ul9wemtFcXNIZVBsV0VUUHciLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4NCwibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoibjBHajdZTUUzMGxkdjBfd1U1ajZfR1A4VVdlUUd2bUdmRGs3ZkJiSUxqSSIsInkiOiJMQmQ4NHExM3F4Z1Awc3VtNVNISDMxWHZJNWpfandlNmJzbFRvODRCZU5BIiwiYWxnIjoiRVMyNTYifSwibm9uY2UiOiJub25jZSB2YWx1ZSIsImNsYWltcyI6eyJlbWFpbCI6ImVtYWlsQGV4YW1wbGUudGxkIn19.UxjiioJ4aMKAyW3EPDtaoQC2huf0jZvBEKnDwvCyX5Bhzvev1vg9PzToDIKhuk7D3J3wnx01fp2kMc_AQONThw';
    private $idTokenJwsWithTooEarlyIat = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6InFsazgxN1BGNzlNbDVjTDlvVTBTQ0UzTDBTT2ZqOXZseHN0eEVUOHltcGciLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5NDYwMTk4MywibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiM0ExZnVOZC1MOEw3MklYMXZpVkp2MklTc29wVFlDU2M2aXc4X1VxNVhQMCIsInkiOiIyUXItNU1oWVYzVHlGcmhXbWpEWml5WVNvUWplMGtmMlliLU5Tbk1GZUw0IiwiYWxnIjoiRVMyNTYifSwibm9uY2UiOiJub25jZSB2YWx1ZSIsImNsYWltcyI6eyJlbWFpbCI6ImVtYWlsQGV4YW1wbGUudGxkIn19.uGFKhERsKccg7bs3_kBGzgHSAJcGgU_1ReivU45k699-y9d_qphZwErjhQApm0yDVEBYFIh2VVHUCePXpItMpA';
    private $idTokenJws = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6Im1peGI1Sm5xZExoX2VTZXBoMnZvTlVsOS1jUXY5VFJqQko4eFNrdVY4TnciLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiTGlQeG5sOUJqWFpEMjV1djNQSTI5Y0VKaHloMUdxcV8yZi1yNkFCVlFGRSIsInkiOiJlYmRoN25JTk5BV3d3bUY1X0pPdThEOVpzVXBNZThMaFByQlBXZUpsaE53IiwiYWxnIjoiRVMyNTYifSwibm9uY2UiOiJub25jZSB2YWx1ZSJ9.u-mhu6ysehF1f-yb9pxnEfmceAqNM93Kxm4bO-JFqIr5-X8171vSiWTNgibnAZv1Qobh8DcKHAB1fK9pCtY_WQ';
    private $idTokenJwsWithClaims = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2ZXIiLCJhdWQiOiJZb3VyIGNsaWVudCIsInN1YiI6IjgtcjI2clZ3ZTFqYzhmRkhneXZHM1RsVDNNMVZHaFpJVnFMaFNDOUdOZEEiLCJleHAiOjE0OTk4NzU5ODMsImlhdCI6MTQ5OTg3MjM4MywibmJmIjoxNDk5ODcyMzgzLCJzdWJfandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZVV2VmdHd2VWZ2hnNkRPbS1haTRXLTRaMmNKRTFaSE1wLWVuelIzUnBiSSIsInkiOiJ0NWZzU0prY0RTMVE0N29Sby11TWhoQ1RWRTZkSzVUMkg3U0lCNlkwT2o0IiwiYWxnIjoiRVMyNTYifSwibm9uY2UiOiJub25jZSB2YWx1ZSIsImNsYWltcyI6eyJlbWFpbCI6ImVtYWlsQGV4YW1wbGUudGxkIn19.r_gH7Hkk6pLUb0Gx1ykRmwEH3iW0ioASmTz3nO5iD8NTCEYRiTonObZiVmMKxN6iAWKaOHBs51OP8CBennMiew';
}
