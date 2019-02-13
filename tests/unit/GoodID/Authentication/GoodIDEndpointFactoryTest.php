<?php

namespace GoodID\Authentication;

use GoodID\Authentication\Endpoint\GoodIDRequestBuilderEndpoint;
use GoodID\Helpers\Acr;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\SessionDataHandlerInterface;
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
    public function itCreatesRequestBuilderEndpoint()
    {
        $serviceLocator = $this->createMock(ServiceLocator::class);

        $serviceLocator->method('getServerConfig')
            ->willReturn($this->createMock(GoodIDServerConfig::class));
        $serviceLocator->method('getSessionDataHandler')
            ->willReturn($this->createMock(SessionDataHandlerInterface::class));
        $serviceLocator->method('getStateNonceHandler')
            ->willReturn($this->createMock(StateNonceHandler::class));

        $endpoint = GoodIDEndpointFactory::createGoodIDEndpoint(
            $serviceLocator,
            'some-client-id',
            $this->createMock(RSAPrivateKey::class),
            $this->createMock(RSAPrivateKey::class),
            $this->createMock(OpenIDRequestSource::class),
            'https://some.redirect.uri',
            Acr::LEVEL_1,
            $this->createMock(IncomingRequest::class),
            0
        );
        $this->assertInstanceOf(GoodIDRequestBuilderEndpoint::class, $endpoint);
    }

}
