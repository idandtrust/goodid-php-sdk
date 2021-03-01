<?php

namespace GoodID\Authentication;

use GoodID\Authentication\Endpoint\InitiateLoginUriBuilder;
use GoodID\Helpers\Acr;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\Helpers\StateNonceHandler;
use GoodID\SecurityLevel;
use GoodID\ServiceLocator;
use GoodID\Helpers\GoodIDPartnerConfig;

class GoodIDEndpointFactoryTest extends \PHPUnit_Framework_TestCase
{
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

        $goodidPartnerConfig = new GoodIDPartnerConfig('some-client-id', 'some-client-secret', $this->createMock(RSAPrivateKey::class), $this->createMock(RSAPrivateKey::class));
        $endpoint = GoodIDEndpointFactory::createInitiateLoginEndpoint(
            $serviceLocator,
            $goodidPartnerConfig,
            $this->createMock(OpenIDRequestSource::class),
            'https://some.redirect.uri',
            $this->createMock(IncomingRequest::class),
            0
        );
        $this->assertInstanceOf(InitiateLoginUriBuilder::class, $endpoint);
    }

}
