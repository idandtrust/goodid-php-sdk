<?php

namespace GoodID\Authentication;

use GoodID\Exception\GoodIDException;
use GoodID\Exception\ValidationException;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\Request\RequestFactory;
use GoodID\Helpers\Request\TokenRequest;
use GoodID\Helpers\Request\UserinfoRequest;
use GoodID\Helpers\Response\ResponseValidator;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\ServiceLocator;
use GoodID\Testing\MockIncomingRequest;

class GoodIDResponseTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Unexpected request method: invalid!
     */
    public function itFailsIfIncomingRequestIsNotGet()
    {
        $request = $this->createMock(IncomingRequest::class);
        $request->expects($this->once())
            ->method('getMethod')
            ->willReturn('invalid');

        $this->createGoodIDResponse([
            'incomingRequest' => $request,
        ]);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     */
    public function itValidatesReceivedState()
    {
        $request = $this->createMock(IncomingRequest::class);
        $request->method('getMethod')->willReturn('GET');
        $request->expects($this->once())
            ->method('getStringParameter')
            ->with($this->equalTo('state'))
            ->willReturn('some invalid state');

        $validator = $this->createMock(ResponseValidator::class);
        $validator->expects($this->once())
            ->method('validateState')
            ->with($this->equalTo('some invalid state'))
            ->willThrowException(new ValidationException("The received state is invalid."));

        $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'responseValidator' => $validator,
        ]);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Neither code nor error parameter is set.
     */
    public function itFailsWhenNeitherCodeNorErrorIsSet()
    {
        $request = new MockIncomingRequest(['state' => null, 'error' => null]);

        $this->createGoodIDResponse([
            'incomingRequest' => $request,
        ]);
    }

    /**
     * @test
     */
    public function inCaseOfErrorStateIsSet()
    {
        $request = new MockIncomingRequest(['error' => 'some error', 'error_description' => 'Some description']);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
        ]);

        $this->assertTrue($goodIdResponse->hasError());
        $this->assertEquals('some error', $goodIdResponse->getError());
        $this->assertEquals('Some description', $goodIdResponse->getErrorDescription());
    }

    /**
     * @test
     */
    public function inCaseOfErrorQueryMethodsAreUnusable()
    {
        $request = new MockIncomingRequest(['error' => 'some error', 'error_description' => 'Some description']);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
        ]);

        try {
            $goodIdResponse->getSub();
            $this->fail('Exception should have been thrown');
        } catch (GoodIDException $ex) {
            // Pass
        }

        try {
            $goodIdResponse->getClaims();
            $this->fail('Exception should have been thrown');
        } catch (GoodIDException $ex) {
            // Pass
        }

        try {
            $goodIdResponse->toJson();
            $this->fail('Exception should have been thrown');
        } catch (GoodIDException $ex) {
            // Pass
        }

        try {
            $goodIdResponse->toArray();
            $this->fail('Exception should have been thrown');
        } catch (GoodIDException $ex) {
            // Pass
        }
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage App-initiated is not set in session!
     */
    public function itFailsIfAppInitiatedIsNotSet()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, null],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, ''],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
        ]);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Redirect uri is not set in session!
     */
    public function itFailsIfRedirectUriIsNotSet()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, ''],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
        ]);
    }

     /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Request source is not set in session!
     */
    public function itFailsIfRequestSourceIsNotSet()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ''],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $userinfoRequest = $this->createMock(UserinfoRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $requestFactory->method('createUserinfoRequest')
            ->willReturn($userinfoRequest);
        $validator = $this->createMock(ResponseValidator::class);

        $validator->method('validateIdToken')
            ->willReturn([]);
        $tokenRequest->method('hasAccessToken')
            ->willReturn(true);
        $validator->method('validateUserinfo')
            ->willReturn([]);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
            'matchingResponseValidation' => true,
        ]);
    }

    /**
     * @test
     */
    public function itCallsTokenEndpoint()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $validator = $this->createMock(ResponseValidator::class);
        $validator->method('validateIdToken')
            ->willReturn([]);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);

        $tokenRequest->expects($this->once())
            ->method('execute');

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
        ]);
    }

    /**
     * @test
     */
    public function itExtractsDataFromIdTokenExceptForClaims()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $validator = $this->createMock(ResponseValidator::class);

        $validator->expects($this->once())
            ->method('validateIdToken')
            ->willReturn([
                'sub' => 'some subject',
                'claims' => [
                    'foo' => 'bar'
                ]
            ]);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
        ]);

        $this->assertEquals('some subject', $goodIdResponse->getSub());
        $this->assertEquals('{}', $goodIdResponse->getClaims()->toJson());
        $this->assertEquals('{"sub":"some subject","claims":[]}', $goodIdResponse->toJson());
        $this->assertEquals(['sub' => 'some subject', 'claims' => []], $goodIdResponse->toArray());
    }

    /**
     * @test
     */
    public function itCombinesClaimsFromUserinfoWithIdToken()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $userinfoRequest = $this->createMock(UserinfoRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $requestFactory->method('createUserinfoRequest')
            ->willReturn($userinfoRequest);
        $validator = $this->createMock(ResponseValidator::class);

        $idToken = [
            'sub' => 'some subject',
            'claims' => [
                'foo' => 'bar',
            ]
        ];
        $userinfo = [
            'sub' => 'some subject',
            'claims' => [
                'bar' => 'baz',
            ]
        ];

        $validator->expects($this->once())
            ->method('validateIdToken')
            ->willReturn($idToken);
        $tokenRequest->expects($this->once())
            ->method('hasAccessToken')
            ->willReturn(true);
        $validator->expects($this->once())
            ->method('validateUserinfo')
            ->willReturn($userinfo);
        $validator->expects($this->once())
            ->method('validateTokensBelongTogether')
            ->with($this->equalTo($idToken), $this->equalTo($userinfo));

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
        ]);

        $this->assertEquals('some subject', $goodIdResponse->getSub());
        $this->assertEquals('{"bar":"baz"}', $goodIdResponse->getClaims()->toJson());
        $this->assertEquals('{"sub":"some subject","claims":{"bar":"baz"}}', $goodIdResponse->toJson());
        $this->assertEquals(['sub' => 'some subject', 'claims' => ['bar' => 'baz']], $goodIdResponse->toArray());
    }

    /**
     *
     * @test
     */
    public function itWorksWithMultipleEncryptionKeys()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $userinfoRequest = $this->createMock(UserinfoRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $requestFactory->method('createUserinfoRequest')
            ->willReturn($userinfoRequest);
        $validator = $this->createMock(ResponseValidator::class);

        $idToken = [
            'sub' => 'some subject',
            'claims' => [
                'foo' => 'bar',
            ]
        ];
        $userinfo = [
            'sub' => 'some subject',
            'claims' => [
                'bar' => 'baz',
            ]
        ];

        $validator->expects($this->once())
            ->method('validateIdToken')
            ->willReturn($idToken);
        $tokenRequest->expects($this->once())
            ->method('hasAccessToken')
            ->willReturn(true);
        $validator->expects($this->once())
            ->method('validateUserinfo')
            ->willReturn($userinfo);
        $validator->expects($this->once())
            ->method('validateTokensBelongTogether')
            ->with($this->equalTo($idToken), $this->equalTo($userinfo));

        $badEncKey = $this->createMock(RSAPrivateKey::class);
        $badEncKey->method('decryptCompactJwe')
            ->willThrowException(new GoodIDException("Key was bad!"));
        $badEncKey->expects($this->once())
            ->method('decryptCompactJwe');

        $goodEncKey = $this->createMock(RSAPrivateKey::class);
        $goodEncKey->method('decryptCompactJwe')
            ->willReturn([]);
        $goodEncKey->expects($this->exactly(2))
            ->method('decryptCompactJwe');

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
            'encryptionKey' => [$badEncKey, $goodEncKey]
        ]);

        $this->assertEquals('some subject', $goodIdResponse->getSub());
        $this->assertEquals('{"bar":"baz"}', $goodIdResponse->getClaims()->toJson());
        $this->assertEquals('{"sub":"some subject","claims":{"bar":"baz"}}', $goodIdResponse->toJson());
        $this->assertEquals(['sub' => 'some subject', 'claims' => ['bar' => 'baz']], $goodIdResponse->toArray());
    }

    /**
     *
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage No key could decrypt: Key was bad!, Key was bad!,
     */
    public function itFailsIfNoEncryptionKeyWorks()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $userinfoRequest = $this->createMock(UserinfoRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $requestFactory->method('createUserinfoRequest')
            ->willReturn($userinfoRequest);
        $validator = $this->createMock(ResponseValidator::class);

        $badEncKey = $this->createMock(RSAPrivateKey::class);
        $badEncKey->method('decryptCompactJwe')
            ->willThrowException(new GoodIDException("Key was bad!"));
        $badEncKey->expects($this->exactly(2))
            ->method('decryptCompactJwe');

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
            'encryptionKey' => [$badEncKey, $badEncKey]
        ]);
    }

    /**
     *
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage $encryptionKeyOrKeys must be RSAPrivateKey or array of RSAPrivateKey's
     */
    public function itFailsIfEncryptionKeyIsNotRsaPrivateKey()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);

        $goodIdResponse = $this->createGoodIDResponse([
            'encryptionKey' => 123
        ]);
    }

    /**
     *
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage $encryptionKeyOrKeys must be RSAPrivateKey or array of RSAPrivateKey's
     */
    public function itFailsIfEncryptionKeysAreNotRsaPrivateKeys()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);

        $goodIdResponse = $this->createGoodIDResponse([
            'encryptionKey' => [$this->createMock(RSAPrivateKey::class), 123]
        ]);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Internal error: sub not set
     */
    public function itFailsIfSubIsNotSet()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);
        $validator = $this->createMock(ResponseValidator::class);
        $validator->method('validateIdToken')
            ->willReturn([]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
        ]);

        $goodIdResponse->getSub();
    }

    /**
     * @test
     */
    public function responseIsValidatedIfContentIsNotEncrypted()
    {
        $requestObjectAsArray = [
            'claims' => [
                'userinfo' => [
                    'bar' => 'baz'
                ]
            ]
        ];

        $userInfo = ['foo' => 'bar'];

        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, $requestObjectAsArray],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $userinfoRequest = $this->createMock(UserinfoRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $requestFactory->method('createUserinfoRequest')
            ->willReturn($userinfoRequest);
        $validator = $this->createMock(ResponseValidator::class);

        $validator->method('validateIdToken')
            ->willReturn([]);
        $tokenRequest->method('hasAccessToken')
            ->willReturn(true);
        $validator->method('validateUserinfo')
            ->willReturn($userInfo);

        $validator->expects($this->once())
            ->method('validateMatchingResponse')
            ->with($this->equalTo($requestObjectAsArray['claims']), $this->equalTo($userInfo));

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
            'matchingResponseValidation' => true,
        ]);
    }

    /**
     * @test
     */
    public function getAccessTokenWorks()
    {
        $requestedClaims = ['bar' => 'baz'];
        $userInfo = ['foo' => 'bar'];

        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, [
                        'iss' => 'client1',
                        "claims" => [
                            "userinfo" => [
                                'bar' => 'baz'
                            ]
                        ]
                    ]
                ],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $userinfoRequest = $this->createMock(UserinfoRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $requestFactory->method('createUserinfoRequest')
            ->willReturn($userinfoRequest);
        $validator = $this->createMock(ResponseValidator::class);

        $validator->method('validateIdToken')
            ->willReturn([]);
        $tokenRequest->method('hasAccessToken')
            ->willReturn(true);
        $tokenRequest->method('getAccessToken')
            ->willReturn('access-token-1');
        $validator->method('validateUserinfo')
            ->willReturn($userInfo);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
            'matchingResponseValidation' => true,
        ]);

        $this->assertTrue($goodIdResponse->hasAccessToken());
        $this->assertEquals($goodIdResponse->getAccessToken(), "access-token-1");
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage We don't have an access token.
     */
    public function getAccessTokenThrowsWhenThereIsNoAccessToken()
    {
        $requestedClaims = ['bar' => 'baz'];
        $userInfo = ['foo' => 'bar'];

        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED, false],
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $userinfoRequest = $this->createMock(UserinfoRequest::class);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $requestFactory->method('createUserinfoRequest')
            ->willReturn($userinfoRequest);
        $validator = $this->createMock(ResponseValidator::class);

        $validator->method('validateIdToken')
            ->willReturn([]);
        $tokenRequest->method('hasAccessToken')
            ->willReturn(false);
        $tokenRequest->method('getAccessToken')
            ->willReturn(null);
        $validator->method('validateUserinfo')
            ->willReturn($userInfo);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
            'matchingResponseValidation' => true,
        ]);

        $this->assertFalse($goodIdResponse->hasAccessToken());
        $goodIdResponse->getAccessToken();
    }

    /**
     *
     * @param array $params
     * @return GoodIDResponse
     */
    private function createGoodIDResponse(array $params = [])
    {
        $serviceLocator = $this->createMock(ServiceLocator::class);
        $serviceLocator->method('getServerConfig')
            ->willReturn(isset($params['goodIdServerConfig']) ? $params['goodIdServerConfig'] : $this->createMock(GoodIDServerConfig::class));
        $serviceLocator->method('getSessionDataHandler')
            ->willReturn(isset($params['sessionDataHandler']) ? $params['sessionDataHandler'] : $this->createMock(SessionDataHandlerInterface::class));
        $serviceLocator->method('getResponseValidator')
            ->willReturn(isset($params['responseValidator']) ? $params['responseValidator'] : $this->createMock(ResponseValidator::class));
        $serviceLocator->method('getRequestFactory')
            ->willReturn(isset($params['requestFactory']) ? $params['requestFactory'] : $this->createMock(RequestFactory::class));

        $clientId = isset($params['clientId']) ? $params['clientId'] : null;
        $clientSecret = isset($params['clientSecret']) ? $params['clientSecret'] : null;
        $signingKey = isset($params['signingKey']) ? $params['signingKey'] : $this->createMock(RSAPrivateKey::class);
        $encryptionKey = isset($params['encryptionKey']) ? $params['encryptionKey'] : $this->createMock(RSAPrivateKey::class);
        $matchingResponseValidation = isset($params['matchingResponseValidation']) ? $params['matchingResponseValidation'] : false;
        $incomingRequest = isset($params['incomingRequest']) ? $params['incomingRequest'] : $this->createMock(IncomingRequest::class);

        return new GoodIDResponse(
            $serviceLocator,
            $clientId,
            $clientSecret,
            $signingKey,
            $encryptionKey,
            $matchingResponseValidation,
            $incomingRequest
        );
    }
}
