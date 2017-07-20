<?php

namespace GoodID\Authentication\Endpoint;

use GoodID\Helpers\Acr;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\SessionDataHandler;
use GoodID\Helpers\StateNonceHandler;
use GoodID\Testing\MockIncomingRequest;

class GoodIDLoginInitiationEndpointTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Request parameter pairing_nonce missing or empty.
     */
    public function itFailsWithoutNonce()
    {
        $request = new MockIncomingRequest([
            'request_uri' => 'http://example.com/some-uri',
            'redirect_uri' => 'http://example.com/some-uri'
        ]);

        $ep = $this->buildEndpoint($request);
        $ep->run();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Request parameter request_uri missing or empty.
     */
    public function itFailsWithoutRequestUri()
    {
        $request = new MockIncomingRequest([
            'pairing_nonce' => 'some-nonce-value',
            'redirect_uri' => 'http://example.com/some-uri'
        ]);

        $ep = $this->buildEndpoint($request);
        $ep->run();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Request parameter redirect_uri missing or empty.
     */
    public function itFailsWithoutRedirectUri()
    {
        $request = new MockIncomingRequest([
            'pairing_nonce' => 'some-nonce-value',
            'request_uri' => 'http://example.com/some-uri',
        ]);

        $ep = $this->buildEndpoint($request);
        $ep->run();
    }

    /**
     * @test
     */
    public function itBuildsRedirectionUrl()
    {
        $request = new MockIncomingRequest([
            'pairing_nonce' => 'some-nonce-value',
            'request_uri' => 'http://example.com/some-uri',
            'redirect_uri' => 'http://example.com/some-uri'
        ]);

        $ep = $this->buildEndpoint($request);
        $url = $ep->buildRedirectionURL();

        $this->assertEquals('endpoint-uri?client_id=some-client-id&pairing_nonce=some-nonce-value&state=mock-state-value', $url);
    }

    private function buildEndpoint(IncomingRequest $request)
    {
        $mockKey = $this->createMock(RSAPrivateKey::class);
        $mockRequestSource = $this->createMock(OpenIDRequestSource::class);
        $mockSessionDataHandler = $this->createMock(SessionDataHandler::class);
        $mockStateNonceHandler = $this->createMock(StateNonceHandler::class);
        $mockStateNonceHandler->method('generateNonce')->willReturn('mock-nonce-value');
        $mockStateNonceHandler->method('generateState')->willReturn('mock-state-value');
        $mockServerConfig = $this->createMock(GoodIDServerConfig::class);
        $mockServerConfig->method('getAuthorizationEndpointUri')->willReturn('endpoint-uri');

        return new GoodIDLoginInitiationEndpoint(
            $request,
            'some-client-id',
            $mockKey,
            $mockKey,
            $mockRequestSource,
            null,
            Acr::LEVEL_DEFAULT,
            $mockServerConfig,
            $mockSessionDataHandler,
            $mockStateNonceHandler
        );
    }
}
