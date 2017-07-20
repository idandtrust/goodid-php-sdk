<?php

namespace GoodID\Helpers\Request;

use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Http\HttpResponse;

class UserinfoRequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Authentication failed to userinfo endpoint:
     */
    public function itFailsWhenAuthorizationFails()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(401);
        $response->expects($this->once())
            ->method('getHeader')
            ->with($this->equalTo('WWW-Authenticate'))
            ->willReturn('error="invalid_token", error_description="Some error message"');

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Userinfo endpoint http status code:
     */
    public function itFailsWhenResponseCodeIsNot200()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(500);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     */
    public function itReturnsWhatItGetsFromEndpoint()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->expects($this->once())
            ->method('getBody')
            ->willReturn('Some jwt userinfo here');

        $request = $this->createRequest($response);
        $request->execute();

        $this->assertEquals('Some jwt userinfo here', $request->getUserInfoJwe());
    }

    /**
     * Partial mock
     *
     * @param HttpResponse $response
     * @return UserinfoRequest|\PHPUnit_Framework_MockObject_MockObject
     */
    private function createRequest(HttpResponse $response)
    {
        $accessToken = 'some-access-token';

        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getUserinfoEndpointURI')
            ->willReturn('userinfo-endpoint');

        $request = $this->getMockBuilder(UserinfoRequest::class)
            ->setConstructorArgs([$accessToken, $serverConfig])
            ->setMethods(['callEndpoint'])
            ->getMock();
        $request->method('callEndpoint')
            ->willReturn($response);

        return $request;
    }
}
