<?php

namespace GoodID\Helpers;

class StateNonceHandlerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itStoresStateInSessionHandler()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->once())
            ->method('set')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_STATE), $this->anything());

        $handler = new StateNonceHandler($sessionDataHandler);
        $handler->generateState();
    }

    /**
     * @test
     */
    public function itStoresNonceInSessionHandler()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->once())
            ->method('set')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE), $this->anything());

        $handler = new StateNonceHandler($sessionDataHandler);
        $handler->generateNonce();
    }

    /**
     * @test
     */
    public function itFailsStateValidationWhenStateIsNotSet()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_STATE))
            ->willReturn(null);

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertFalse($handler->validateState('1234567890123456789012'));
    }

    /**
     * @test
     */
    public function itFailsStateValidationWhenSetStateDiffers()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_STATE))
            ->willReturn('a234567890123456789012');

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertFalse($handler->validateState('b234567890123456789012'));
    }

    /**
     * @test
     */
    public function itPassesStateValidationIfStoredAndReceivedStatesAreEqual()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_STATE))
            ->willReturn('1234567890123456789012');

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertTrue($handler->validateState('1234567890123456789012'));
    }

    /**
     * @test
     */
    public function itClearsSetStateAfterPassingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_STATE))
            ->willReturn('1234567890123456789012');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_STATE));

        (new StateNonceHandler($sessionDataHandler))
            ->validateState('1234567890123456789012');
    }

    /**
     * @test
     */
    public function itClearsSetStateAfterFailingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_STATE))
            ->willReturn('a234567890123456789012');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_STATE));

        (new StateNonceHandler($sessionDataHandler))
            ->validateState('b234567890123456789012');
    }

    /**
     * @test
     */
    public function itFailsNonceValidationWhenNonceIsNotSet()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE))
            ->willReturn(null);

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertFalse($handler->validateNonce('1234567890123456789012', 'dummy-client-secret', 0, 0));
    }

    /**
     * @test
     */
    public function itFailsNonceValidationWhenSetNonceDiffers()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE))
            ->willReturn('a234567890123456789012');

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertFalse($handler->validateNonce('b234567890123456789012', 'dummy-client-secret', 0, 0));
    }

    /**
     * @test
     */
    public function itPassesNonceValidationIfStoredAndReceivedNoncesAreEqual()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE))
            ->willReturn('1234567890123456789012');

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertTrue($handler->validateNonce('1234567890123456789012', 'dummy-client-secret', 0, 0));
    }

     /**
     * @test
     */
    public function itClearsSetNonceAfterPassingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE))
            ->willReturn('1234567890123456789012');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE));

        (new StateNonceHandler($sessionDataHandler))
            ->validateNonce('1234567890123456789012', 'dummy-client-secret', 0, 0);
    }

    /**
     * @test
     */
    public function itClearsSetNonceAfterFailingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE))
            ->willReturn('a234567890123456789012');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE));

        (new StateNonceHandler($sessionDataHandler))
            ->validateNonce('b234567890123456789012', 'dummy-client-secret', 0, 0);
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage The nonce has invalid length
     */
    public function itThrowsOnBadNonceLength()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandlerInterface::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandlerInterface::SESSION_KEY_NONCE))
            ->willReturn(null);

        (new StateNonceHandler($sessionDataHandler))
            ->validateNonce('123456789012345678901', 'dummy-client-secret', 0, 0);
    }
}
