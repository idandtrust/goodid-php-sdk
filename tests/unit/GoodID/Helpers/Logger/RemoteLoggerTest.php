<?php

namespace GoodID\Helpers\Logger;

use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Http\HttpResponse;
use GoodID\Helpers\Logger\Log;

class RemoteLoggerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage GoodID remote logging endpoint returned 401, problem
     */
    public function itFailsWhenHttpStatusCodeIsNotOk()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(401);
        $response->method('getBody')
            ->willReturn('problem');

        $logger = $this->createRemoteLogger($response);
        $logger->log('phone_number', '06 123: bad phone_number format');
        $logger->send();
    }

    /**
     * @test
     */
    public function itDoesNotSendEmptyLog()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);

        $logger = $this->createRemoteLogger($response);

        $logger->expects($this->never())
            ->method('callEndpoint');

        $logger->send();
    }

    /**
     * @test
     */
    public function itClearsLogsWhenSent()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);

        $logger = $this->createRemoteLogger($response);

        $logger->log('phone_number', '06 123: bad phone_number format');
        $logger->log('billto.phone_number', '06 123: bad billto.phone_number format');
        $logger->send();

        $logger->expects($this->never())
            ->method('callEndpoint');

        $logger->send();
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage $claimName must be a non-empty string
     */
    public function itFailsWhenClaimNameIsEmpty()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);

        $logger = $this->createRemoteLogger($response);
        $logger->log("", "asdf");
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage $claimName must be a non-empty string
     */
    public function itFailsWhenClaimNameIsNotString()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);

        $logger = $this->createRemoteLogger($response);
        $logger->log(33, "error description");
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage $errorDescription must be a non-empty string
     */
    public function itFailsWhenErrorDescriptionIsEmpty()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);

        $logger = $this->createRemoteLogger($response);
        $logger->log("name", "");
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage $errorDescription must be a non-empty string
     */
    public function itFailsWhenErrorDescriptionIsNotString()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);

        $logger = $this->createRemoteLogger($response);
        $logger->log("name", 33);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage $logLevel is invalid
     */
    public function itFailsWhenLogLevelIsInvalid()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);

        $logger = $this->createRemoteLogger($response);
        $logger->log("name", "error description", "errrror");
    }

    /**
     * @test
     */
    public function itSendsCorrectLogs()
    {
        $response = $this->createMock(HttpResponse::class);
        $response->method('getHttpStatusCode')
            ->willReturn(200);

        $logger = $this->createRemoteLogger($response);

        $logger->log('phone_number', '06 123: bad phone_number format');
        $logger->log('billto.phone_number', '06 123: bad billto.phone_number format', Log::LEVEL_NOTICE);

        $logger->expects($this->once())
            ->method('callEndpoint')
            ->with(
                $this->equalTo('remote-logging-endpoint'),
                $this->equalTo('some-access-token'),
                $this->equalTo(json_encode($this->messageArray))
            );

        $logger->send();
    }


     /**
     * Partial mock
     *
     * @param HttpResponse $response
     * @return RemoteLogger|\PHPUnit_Framework_MockObject_MockObject
     */
    private function createRemoteLogger(HttpResponse $response)
    {
        $accessToken = 'some-access-token';

        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getRemoteLoggingEndpointUri')
            ->willReturn('remote-logging-endpoint');

        $logger = $this->getMockBuilder(RemoteLogger::class)
            ->setConstructorArgs([$accessToken, $serverConfig])
            ->setMethods(['callEndpoint'])
            ->getMock();
        $logger->method('callEndpoint')
            ->willReturn($response);

        return $logger;
    }

    /**
     * @var array
     */
    private $messageArray = [
        "log_entries" => [
            [
                "log_level" => "error",
                "claim_name" => "phone_number",
                "error_description" => "06 123: bad phone_number format"
            ],
            [
                "log_level" => "notice",
                "claim_name" => "billto.phone_number",
                "error_description" => "06 123: bad billto.phone_number format"
            ]
        ]
    ];
}
