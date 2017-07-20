<?php

namespace GoodID\Authentication;

use GoodID\Authentication\Endpoint\GoodIDLoginInitiationEndpoint;
use GoodID\Authentication\Endpoint\GoodIDRequestBuilderEndpoint;
use GoodID\Helpers\Acr;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\SessionDataHandler;
use GoodID\Helpers\StateNonceHandler;
use GoodID\ServiceLocator;

class GoodIDEndpointFactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Invalid ACR
     */
    public function itFailsWhenAcrIsInvalid()
    {
        $serviceLocator = $this->createMock(ServiceLocator::class);
        $invalidACR = 12;
        $mockKey = $this->createMock(RSAPrivateKey::class);
        $mockRequestSource = $this->createMock(OpenIDRequestSource::class);

        GoodIDEndpointFactory::createGoodIDEndpoint(
            $serviceLocator,
            null,
            $mockKey,
            $mockKey,
            $mockRequestSource,
            null,
            $invalidACR,
            null
        );
    }

    /**
     * @test
     */
    public function itCreatesLoginInitEndpoint()
    {
        $serviceLocator = $this->createMock(ServiceLocator::class);
        $serviceLocator->method('getServerConfig')
            ->willReturn($this->createMock(GoodIDServerConfig::class));
        $serviceLocator->method('getSessionDataHandler')
            ->willReturn($this->createMock(SessionDataHandler::class));
        $serviceLocator->method('getStateNonceHandler')
            ->willReturn($this->createMock(StateNonceHandler::class));
        $mockKey = $this->createMock(RSAPrivateKey::class);
        $mockRequestSource = $this->createMock(OpenIDRequestSource::class);
        $request = $this->createMock(IncomingRequest::class);
        $request->method('getMethod')
            ->willReturn('GET');
        $request->method('getOrigin')
            ->willReturn('app');

        $endpoint = GoodIDEndpointFactory::createGoodIDEndpoint(
            $serviceLocator,
            'some-client-id',
            $mockKey,
            $mockKey,
            $mockRequestSource,
            null,
            Acr::LEVEL_DEFAULT,
            $request
        );
        $this->assertInstanceOf(GoodIDLoginInitiationEndpoint::class, $endpoint);
    }

    /**
     * @test
     */
    public function itCreatesRequestBuilderEndpoint()
    {
        $serviceLocator = $this->createMock(ServiceLocator::class);
        $serviceLocator->method('getServerConfig')
            ->willReturn($this->createMock(GoodIDServerConfig::class));
        $serviceLocator->method('getSessionDataHandler')
            ->willReturn($this->createMock(SessionDataHandler::class));
        $serviceLocator->method('getStateNonceHandler')
            ->willReturn($this->createMock(StateNonceHandler::class));
        $mockKey = $this->createMock(RSAPrivateKey::class);
        $mockRequestSource = $this->createMock(OpenIDRequestSource::class);
        $request = $this->createMock(IncomingRequest::class);
        $request->method('getMethod')
            ->willReturn('POST');
        $request->method('getOrigin')
            ->willReturn('browser');

        $endpoint = GoodIDEndpointFactory::createGoodIDEndpoint(
            $serviceLocator,
            'some-client-id',
            $mockKey,
            $mockKey,
            $mockRequestSource,
            null,
            Acr::LEVEL_DEFAULT,
            $request
        );
        $this->assertInstanceOf(GoodIDRequestBuilderEndpoint::class, $endpoint);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Unsupported request.
     */
    public function itFailsForOtherRequests()
    {
        $serviceLocator = $this->createMock(ServiceLocator::class);
        $mockKey = $this->createMock(RSAPrivateKey::class);
        $mockRequestSource = $this->createMock(OpenIDRequestSource::class);
        $request = $this->createMock(IncomingRequest::class);

        GoodIDEndpointFactory::createGoodIDEndpoint(
            $serviceLocator,
            null,
            $mockKey,
            $mockKey,
            $mockRequestSource,
            null,
            Acr::LEVEL_DEFAULT,
            $request
        );
    }
}
