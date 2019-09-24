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
use GoodID\Helpers\Response\IdTokenVerifier;
use GoodID\Helpers\Response\ResponseValidator;
use GoodID\Helpers\Response\TokenExtractor;
use GoodID\Helpers\Response\UserinfoVerifier;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\Helpers\StateNonceHandler;
use GoodID\ServiceLocator;
use GoodID\Testing\MockIncomingRequest;
use Jose\Factory\JWSFactory;
use Jose\Object\JWK;
use Jose\Object\JWKSet;

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

        $stateNonceHandler = $this->createMock(StateNonceHandler::class);
        $stateNonceHandler->expects($this->once())
            ->method('validateState')
            ->with($this->equalTo('some invalid state'))
            ->willThrowException(new ValidationException("The received state is invalid."));

        $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'stateNonceHandler' => $stateNonceHandler,
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
     * @expectedExceptionMessage Redirect uri is not set in session!
     */
    public function itFailsIfRedirectUriIsNotSet()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
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

        $tokenRequest->method('hasAccessToken')
            ->willReturn(true);

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

        $tokenRequest->expects($this->once())
            ->method('execute');

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
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

        $idToken = JWSFactory::createJWS(['sub' => 'some subject', 'foo' => 'baz']);
        $userinfo = JWSFactory::createJWS(['sub' => 'some subject']);
        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $tokenExtractor->method('extractToken')
            ->willReturnOnConsecutiveCalls($idToken, $userinfo);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'tokenExtractor' => $tokenExtractor,
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

        $idToken = JWSFactory::createJWS(['sub' => 'some subject', 'foo' => 'bar']);
        $userinfo = JWSFactory::createJWS(['sub' => 'some subject', 'bar' => 'baz']);
        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $tokenExtractor->method('extractToken')
            ->willReturnOnConsecutiveCalls($idToken, $userinfo);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
            'tokenExtractor' => $tokenExtractor,
        ]);

        $this->assertEquals('some subject', $goodIdResponse->getSub());
        $this->assertEquals('{"bar":"baz"}', $goodIdResponse->getClaims()->toJson());
        $this->assertEquals('{"sub":"some subject","claims":{"bar":"baz"}}', $goodIdResponse->toJson());
        $this->assertEquals(['sub' => 'some subject', 'claims' => ['bar' => 'baz']], $goodIdResponse->toArray());
    }

    /**
     * @test
     */
    public function itUsesTokenExtractor()
    {
        $idTokenResponse = 'idToken';
        $userinfoResponse = 'userinfo';

        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                [SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI, 'http://redirect.uri'],
                [SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE, ['iss' => 'client1']],
            ]);
        $tokenRequest = $this->createMock(TokenRequest::class);
        $tokenRequest->expects($this->once())->method('getIdTokenJwe')->willReturn($idTokenResponse);
        $userinfoRequest = $this->createMock(UserinfoRequest::class);
        $userinfoRequest->expects($this->once())->method('getUserinfoJwe')->willReturn($userinfoResponse);
        $requestFactory = $this->createMock(RequestFactory::class);
        $requestFactory->method('createTokenRequest')
            ->willReturn($tokenRequest);
        $requestFactory->method('createUserinfoRequest')
            ->willReturn($userinfoRequest);

        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $tokenExtractor->expects($this->exactly(2))
            ->method('extractToken')
            ->withConsecutive([$idTokenResponse], [$userinfoResponse])
            ->willReturn(JWSFactory::createJWS([]));
            ;

        $response = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'tokenExtractor' => $tokenExtractor,
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

        $idToken = JWSFactory::createJWS([]);
        $userinfo = JWSFactory::createJWS([]);
        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $tokenExtractor->method('extractToken')
            ->willReturnOnConsecutiveCalls($idToken, $userinfo);

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'tokenExtractor' => $tokenExtractor,
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

        $userInfoClaims = ['foo' => 'bar'];

        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
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

        $idToken = JWSFactory::createJWS([]);
        $userinfo = JWSFactory::createJWS($userInfoClaims);
        $tokenExtractor = $this->createMock(TokenExtractor::class);
        $tokenExtractor->method('extractToken')->willReturnOnConsecutiveCalls($idToken, $userinfo);
        $tokenRequest->method('hasAccessToken')->willReturn(true);

        $validator->expects($this->once())
            ->method('validateMatchingResponse')
            ->with($this->equalTo($requestObjectAsArray['claims']), $this->equalTo($userinfo->getClaims()));

        $goodIdResponse = $this->createGoodIDResponse([
            'incomingRequest' => $request,
            'sessionDataHandler' => $sessionDataHandler,
            'requestFactory' => $requestFactory,
            'responseValidator' => $validator,
            'matchingResponseValidation' => true,
            'tokenExtractor' => $tokenExtractor,
        ]);
    }

    /**
     * @test
     */
    public function getAccessTokenWorks()
    {
        $request = new MockIncomingRequest(['code' => 'some-auth-code']);
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
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

        $tokenRequest->method('hasAccessToken')
            ->willReturn(true);
        $tokenRequest->method('getAccessToken')
            ->willReturn('access-token-1');

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
     *
     * @param array $params
     * @return GoodIDResponse
     */
    private function createGoodIDResponse(array $params = [])
    {
        $serviceLocator = $this->createMock(ServiceLocator::class);
        if (isset($params['goodIdServerConfig'])) {
            $serverConfig = $params['goodIdServerConfig'];
        } else {
            $serverConfig = $this->createMock(GoodIDServerConfig::class);
            $serverConfig
                ->method('getKeystore')
                ->willReturn(new JWKSet(['keys' => [['kty' => 'none']]]));
        }
        $serviceLocator->method('getServerConfig')
            ->willReturn($serverConfig);
        $serviceLocator->method('getSessionDataHandler')
            ->willReturn(isset($params['sessionDataHandler']) ? $params['sessionDataHandler'] : $this->createMock(SessionDataHandlerInterface::class));
        $serviceLocator->method('getResponseValidator')
            ->willReturn(isset($params['responseValidator']) ? $params['responseValidator'] : $this->createMock(ResponseValidator::class));
        $serviceLocator->method('getRequestFactory')
            ->willReturn(isset($params['requestFactory']) ? $params['requestFactory'] : $this->createMock(RequestFactory::class));
        if (isset($params['tokenExtractor'])) {
            $tokenExtractor = $params['tokenExtractor'];
        } else {
            $tokenExtractor = $this->createMock(TokenExtractor::class);
//            $token = JWSFactory::createJWS([]);
//            $token = $token->addSignatureInformation(new JWK(['kty' => 'none']), ['alg' => 'ES-256']);
//            $tokenExtractor
//                ->method('extractToken')
//                ->willReturn($token);
            $tokenExtractor->method('extractToken')->willReturn(JWSFactory::createJWS([]));
        }
        $serviceLocator->method('getTokenExtractor')->willReturn($tokenExtractor);
        $serviceLocator->method('getIdTokenVerifier')->willReturn($this->createMock(IdTokenVerifier::class));
        $serviceLocator->method('getUserinfoVerifier')->willReturn($this->createMock(UserinfoVerifier::class));
        if (isset($params['stateNonceHandler'])) {
            $stateNonceHandler = $params['stateNonceHandler'];
        } else {
            $stateNonceHandler = $this->createMock(StateNonceHandler::class);
            $stateNonceHandler
                ->method('validateState')
                ->willReturn(true);
        }
        $serviceLocator->method('getStateNonceHandler')
            ->willReturn($stateNonceHandler);

        $clientId = isset($params['clientId']) ? $params['clientId'] : null;
        $clientSecret = isset($params['clientSecret']) ? $params['clientSecret'] : null;
        $signingKey = isset($params['signingKey']) ? $params['signingKey'] : $this->createMock(RSAPrivateKey::class);
        if (isset($params['encryptionKey'])) {
            $encryptionKey = $params['encryptionKey'];
        } else {
            $encryptionKey = $this->createMock(RSAPrivateKey::class);
            $encryptionKey
                ->method('asSpomkyKey')
                ->willReturn(new JWK(['kty' => 'none']))
            ;
        }
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
