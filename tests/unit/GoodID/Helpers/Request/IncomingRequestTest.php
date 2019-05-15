<?php

namespace GoodID\Helpers\Request;

use org\bovigo\vfs\vfsStream;

class IncomingRequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCanBeCreatedForGetRequests()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $request = new IncomingRequest();

        $this->assertInstanceOf(IncomingRequest::class, $request);
        $this->assertEquals('GET', $request->getMethod());
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Unsupported request method.
     */
    public function itCanNotBeCreatedForPostRequests()
    {
        $this->markTestIncomplete();
        return;

        $_SERVER['REQUEST_METHOD'] = 'POST';

        $request = new IncomingRequest($this->getMockInput('{}'));

        $this->assertInstanceOf(IncomingRequest::class, $request);
    }

    /**
     * @test
     */
    public function itReturnsEmptyStringForNonExistentParams()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $request = new IncomingRequest();

        $this->assertEquals('', $request->getStringParameter('missing'));
    }

    /**
     * @test
     */
    public function itExtractsParamValuesTrimmed()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $_GET['some-param'] = 'some-value';
        $_GET['other-param'] = '   padded with whitespace   ';

        $request = new IncomingRequest();

        $this->assertEquals('some-value', $request->getStringParameter('some-param'));
        $this->assertEquals('padded with whitespace', $request->getStringParameter('other-param'));
    }

    protected function setUp()
    {
        $this->vfsRoot = vfsStream::setup();
    }

    private $vfsRoot;

    private function getMockInput($content)
    {
        return vfsStream::newFile('input')
            ->withContent($content)
            ->at($this->vfsRoot)
            ->url();
    }
}
