<?php

namespace GoodID\Helpers\Request;

use GoodID\Exception\GoodIDException;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Http\HttpResponse;

// Override php function for testing
function error_log($message)
{
    TokenRequestTest::$gatheredLogs[] = $message;
}

function trigger_error($message, $logLevel)
{
    TokenRequestTest::$gatheredLogs[] = $message;
}

class TokenRequestTest extends \PHPUnit_Framework_TestCase
{
    public static $gatheredLogs;

    protected function setUp()
    {
        self::$gatheredLogs = [];
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage GoodID Token endpoint response is invalid.
     */
    public function itFailsOnInvalidResponse()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->expects($this->once())
            ->method('getBodyJsonDecoded')
            ->willReturn(null);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Token endpoint http status code:
     */
    public function itFailsWhenResponseCodeIsNot200()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(500);
        $response->method('getBodyJsonDecoded')
            ->willReturn([]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage GoodID Token Endpoint Error: Some error:
     */
    public function itFailsOnErrorResponse1()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error' => 'Some error'
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage GoodID Token Endpoint Error: Some error: with description
     */
    public function itFailsOnErrorResponse2()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error' => 'Some error',
                'error_description' => 'with description',
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage GoodID Token Endpoint Error: Some error: See: http://some.uri
     */
    public function itFailsOnErrorResponse3()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error' => 'Some error',
                'error_uri' => 'http://some.uri',
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage GoodID Token Endpoint Error: Some error: with description See: http://some.uri
     */
    public function itFailsOnErrorResponse4()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error' => 'Some error',
                'error_description' => 'with description',
                'error_uri' => 'http://some.uri',
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     */
    public function itFailsOnWarningResponse1()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error_type' => 'warning',
                'error' => 'Some error',
            ]);

        try {
            $this->createRequest($response)->execute();
        } catch (GoodIDException $ex) {
            // Noop; fails, but because of missing content
        }

        $this->assertEquals(self::$gatheredLogs[0], 'GoodID Token Endpoint Warning: Some error:');
    }

    /**
     * @test
     */
    public function itFailsOnWarningResponse2()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error_type' => 'warning',
                'error' => 'Some error',
                'error_description' => 'with description',
            ]);

        try {
            $this->createRequest($response)->execute();
        } catch (GoodIDException $ex) {
            // Noop; fails, but because of missing content
        }

        $this->assertEquals(self::$gatheredLogs[0], 'GoodID Token Endpoint Warning: Some error: with description');
    }

    /**
     * @test
     */
    public function itFailsOnWarningResponse3()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error_type' => 'warning',
                'error' => 'Some error',
                'error_uri' => 'http://some.uri',
            ]);

        try {
            $this->createRequest($response)->execute();
        } catch (GoodIDException $ex) {
            // Noop; fails, but because of missing content
        }

        $this->assertEquals(self::$gatheredLogs[0], 'GoodID Token Endpoint Warning: Some error: See: http://some.uri');
    }

    /**
     * @test
     */
    public function itFailsOnWarningResponse4()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error_type' => 'warning',
                'error' => 'Some error',
                'error_description' => 'with description',
                'error_uri' => 'http://some.uri',
            ]);

        try {
            $this->createRequest($response)->execute();
        } catch (GoodIDException $ex) {
            // Noop; fails, but because of missing content
        }

        $this->assertEquals(self::$gatheredLogs[0],
            'GoodID Token Endpoint Warning: Some error: with description See: http://some.uri');
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage GoodID Token Endpoint Error
     */
    public function itFailsOnErrorUnknownErrorType()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'error_type' => 'invalid',
                'error' => 'Some error',
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Token Response content error:
     */
    public function itValidatesContentMissingIdToken()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'server_time' => 1499774246,
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Token Response content error:
     */
    public function itValidatesContentMissingServerTime()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'id_token' => 'some-id-token',
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Token Response content error:
     */
    public function itValidatesContentAccessTokenWithMissingType()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'id_token' => 'some-id-token',
                'server_time' => 1499774246,
                'access_token' => 'some-access-token',
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Token Response content error:
     */
    public function itValidatesContentAccessTokenWithWrongType()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'id_token' => 'some-id-token',
                'server_time' => 1499774246,
                'access_token' => 'some-access-token',
                'token_type' => 'invalid',
            ]);

        $this->createRequest($response)->execute();
    }

    /**
     * @test
     */
    public function itRetrievesIdTokenWithAccessToken()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);
        $response->method('getBodyJsonDecoded')
            ->willReturn([
                'id_token' => 'some-id-token',
                'server_time' => 1499774246,
                'access_token' => 'some-access-token',
                'token_type' => 'Bearer',
            ]);

        $request = $this->createRequest($response);
        $request->execute();

        $this->assertEquals('some-id-token', $request->getIdTokenJwe());
        $this->assertEquals(1499774246, $request->getGoodIDServerTime());
        $this->assertTrue($request->hasAccessToken());
        $this->assertEquals('some-access-token', $request->getAccessToken());
    }

    /**
     * Partial mock
     *
     * @param HttpResponse $response
     * @return TokenRequest|\PHPUnit_Framework_MockObject_MockObject
     */
    private function createRequest(HttpResponse $response)
    {
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getTokenEndpointUri')
            ->willReturn('token-endpoint');

        $request = $this->getMockBuilder(TokenRequest::class)
            ->setConstructorArgs([
                'client-id',
                'client-secret',
                'http://redirect.uri',
                'auth-code',
                'http://request.uri',
                $serverConfig
            ])
            ->setMethods(['callEndpoint'])
            ->getMock();
        $request->method('callEndpoint')
            ->willReturn($response);

        return $request;
    }
}
