<?php

namespace GoodID\Authentication\Endpoint;

use GoodID\Helpers\Acr;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObject;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObjectJWT;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestURI;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\SessionDataHandler;
use GoodID\Helpers\StateNonceHandler;
use GoodID\Testing\MockIncomingRequest;

class GoodIDRequestBuilderEndpointTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Request parameter endpoint_uri missing or empty.
     */
    public function itFailsWithoutEndpointUri()
    {
        $request = new MockIncomingRequest([
            'current_url' => 'https://current.url',
            'display' => 'page',
        ]);

        $ep = $this->buildEndpoint($request);
        $ep->run();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Request parameter current_url missing or empty.
     */
    public function itFailsWithoutCurrentUrl()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'display' => 'page',
        ]);

        $ep = $this->buildEndpoint($request);
        $ep->run();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Request parameter display missing or empty.
     */
    public function itFailsWithoutDisplay()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'current_url' => 'https://current.url',
        ]);

        $ep = $this->buildEndpoint($request);
        $ep->run();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Unsupported OpenIDRequestSource
     */
    public function itFailsWithUnknownRequestSource()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'current_url' => 'https://current.url',
            'display' => 'page',
        ]);

        $ep = $this->buildEndpoint($request);
        $ep->run();
    }

    /**
     * @test
     */
    public function itCreatesRequestUrlUsingRequestUri()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'current_url' => 'https://current.url',
            'display' => 'page',
        ]);

        $requestSource = $this->createMock(OpenIDRequestURI::class);
        $requestSource->method('getRequestUri')
            ->willReturn('https://some.request.uri');

        $ep = $this->buildEndpoint($request, $requestSource);
        $url = $ep->buildRequestUrl();
        $this->assertStringStartsWith('endpoint-uri?', $url);

        parse_str(parse_url($url, PHP_URL_QUERY), $query);
        $this->assertEquals('code', $query['response_type']);
        $this->assertEquals('client-id', $query['client_id']);
        $this->assertEquals('openid', $query['scope']);
        $this->assertEquals('mock-state-value', $query['state']);
        $this->assertEquals('mock-nonce-value', $query['nonce']);
        $this->assertEquals('page', $query['display']);
        $this->assertArrayHasKey('ui_locales', $query);
        $this->assertArrayHasKey('sdk_version', $query);

        $this->assertEquals('https://some.request.uri', $query['request_uri']);
    }

    /**
     * @test
     */
    public function itCreatesRequestUrlUsingRequestObject()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'current_url' => 'https://current.url',
            'display' => 'page',
        ]);

        $requestSource = $this->createMock(OpenIDRequestObject::class);
        $requestSource->method('generateJwt')
            ->willReturn('a-signed-jwt');

        $ep = $this->buildEndpoint($request, $requestSource);
        $url = $ep->buildRequestUrl();
        $this->assertStringStartsWith('endpoint-uri?', $url);

        parse_str(parse_url($url, PHP_URL_QUERY), $query);
        $this->assertEquals('code', $query['response_type']);
        $this->assertEquals('client-id', $query['client_id']);
        $this->assertEquals('openid', $query['scope']);
        $this->assertEquals('mock-state-value', $query['state']);
        $this->assertEquals('mock-nonce-value', $query['nonce']);
        $this->assertEquals('page', $query['display']);
        $this->assertArrayHasKey('ui_locales', $query);
        $this->assertArrayHasKey('sdk_version', $query);

        $this->assertEquals('a-signed-jwt', $query['request']);
    }

    /**
     * @test
     */
    public function itCreatesRequestUrlUsingRequestObjectJWT()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'current_url' => 'https://current.url',
            'display' => 'page',
        ]);

        $requestSource = $this->createMock(OpenIDRequestObjectJWT::class);
        $requestSource->method('getJwt')
            ->willReturn('a-jwt');

        $ep = $this->buildEndpoint($request, $requestSource);
        $url = $ep->buildRequestUrl();
        $this->assertStringStartsWith('endpoint-uri?', $url);

        parse_str(parse_url($url, PHP_URL_QUERY), $query);
        $this->assertEquals('code', $query['response_type']);
        $this->assertEquals('client-id', $query['client_id']);
        $this->assertEquals('openid', $query['scope']);
        $this->assertEquals('mock-state-value', $query['state']);
        $this->assertEquals('mock-nonce-value', $query['nonce']);
        $this->assertEquals('page', $query['display']);
        $this->assertArrayHasKey('ui_locales', $query);
        $this->assertArrayHasKey('sdk_version', $query);

        $this->assertEquals('a-jwt', $query['request']);
    }

    /**
     * @test
     */
    public function itCallsSessionDataHandlerWhenUsingRequestUri()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'current_url' => 'https://current.url',
            'display' => 'page',
        ]);

        $requestSource = $this->createMock(OpenIDRequestURI::class);
        $requestSource->method('getRequestUri')
            ->willReturn('https://some.request.uri');

        $ep = $this->buildEndpoint($request, $requestSource);

        $this->mockSessionDataHandler->expects($this->once())
            ->method('removeAll');
        $this->mockSessionDataHandler->expects($this->any())
            ->method('set')
            ->withConsecutive(
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_EXTERNALLY_INITIATED),
                    $this->equalTo(false)
                ],
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_USED_REDIRECT_URI),
                    $this->equalTo('https://redirect.uri')
                ],
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_USED_REQUEST_URI),
                    $this->equalTo('https://some.request.uri')
                ]
            );

        $url = $ep->buildRequestUrl();
    }

    /**
     * @test
     */
    public function itCallsSessionDataHandlerWhenUsingRequestObject()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'current_url' => 'https://current.url',
            'display' => 'page',
        ]);

        $requestSource = $this->createMock(OpenIDRequestObject::class);
        $requestSource->method('generateJwt')
            ->willReturn('a-signed-jwt');

        $ep = $this->buildEndpoint($request, $requestSource);

        $claims = [
            'sub' => 'some-subject-id',
            'name' => 'John Doe',
        ];

        $requestSource->expects($this->once())
            ->method('getClaims')
            ->willReturn($claims);

        $this->mockSessionDataHandler->expects($this->once())
            ->method('removeAll');
        $this->mockSessionDataHandler->expects($this->any())
            ->method('set')
            ->withConsecutive(
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_EXTERNALLY_INITIATED),
                    $this->equalTo(false)
                ],
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_USED_REDIRECT_URI),
                    $this->equalTo('https://redirect.uri')
                ],
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_REQUESTED_CLAIMS),
                    $this->equalTo($claims)
                ]
            );

        $url = $ep->buildRequestUrl();
    }

    /**
     * @test
     */
    public function itCallsSessionDataHandlerWhenUsingRequestObjectJWT()
    {
        $request = new MockIncomingRequest([
            'endpoint_uri' => 'https://some.endpoint.uri',
            'current_url' => 'https://current.url',
            'display' => 'page',
        ]);

        $requestSource = $this->createMock(OpenIDRequestObjectJWT::class);
        $requestSource->method('getJwt')
            ->willReturn('a-jwt');

        $ep = $this->buildEndpoint($request, $requestSource);

        $claims = [
            'sub' => 'some-subject-id',
            'name' => 'John Doe',
        ];

        $requestSource->expects($this->once())
            ->method('getClaims')
            ->willReturn($claims);

        $this->mockSessionDataHandler->expects($this->once())
            ->method('removeAll');
        $this->mockSessionDataHandler->expects($this->any())
            ->method('set')
            ->withConsecutive(
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_EXTERNALLY_INITIATED),
                    $this->equalTo(false)
                ],
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_USED_REDIRECT_URI),
                    $this->equalTo('https://redirect.uri')
                ],
                [
                    $this->equalTo(SessionDataHandler::SESSION_KEY_REQUESTED_CLAIMS),
                    $this->equalTo($claims)
                ]
            );

        $url = $ep->buildRequestUrl();
    }

    private function buildEndpoint(IncomingRequest $request, OpenIDRequestSource $requestSource = null)
    {
        $signingKey = $this->createMock(RSAPrivateKey::class);
        $encryptionKey = $this->createMock(RSAPrivateKey::class);
        $requestSource = $requestSource ?: $this->createMock(OpenIDRequestSource::class);
        $this->mockSessionDataHandler = $this->createMock(SessionDataHandler::class);
        $mockStateNonceHandler = $this->createMock(StateNonceHandler::class);
        $mockStateNonceHandler->method('generateNonce')->willReturn('mock-nonce-value');
        $mockStateNonceHandler->method('generateState')->willReturn('mock-state-value');
        $mockServerConfig = $this->createMock(GoodIDServerConfig::class);
        $mockServerConfig->method('getAuthorizationEndpointUri')->willReturn('endpoint-uri');

        return new GoodIDRequestBuilderEndpoint(
            $request,
            'client-id',
            $signingKey,
            $encryptionKey,
            $requestSource,
            'https://redirect.uri',
            Acr::LEVEL_DEFAULT,
            $mockServerConfig,
            $this->mockSessionDataHandler,
            $mockStateNonceHandler
        );
    }

    /**
     * @var SessionDataHandler|\PHPUnit_Framework_MockObject_MockObject
     */
    private $mockSessionDataHandler;
}
