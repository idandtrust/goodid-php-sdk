<?php

namespace GoodID\Helpers\Request;

use GoodID\Helpers\GoodIDServerConfig;

class RequestFactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCreatesTokenRequest()
    {
        $goodIdServerConfig = $this->createMock(GoodIDServerConfig::class);

        $requestFactory = new RequestFactory();
        $request = $requestFactory->createTokenRequest($goodIdServerConfig, null, null, null, null, null);

        $this->assertInstanceOf(TokenRequest::class, $request);
    }

    /**
     * @test
     */
    public function itCreatesUserinfoRequest()
    {
        $goodIdServerConfig = $this->createMock(GoodIDServerConfig::class);

        $requestFactory = new RequestFactory();
        $request = $requestFactory->createUserinfoRequest($goodIdServerConfig, null);

        $this->assertInstanceOf(UserinfoRequest::class, $request);
    }
}
