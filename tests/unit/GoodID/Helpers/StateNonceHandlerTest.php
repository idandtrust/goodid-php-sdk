<?php

namespace GoodID\Helpers;

class StateNonceHandlerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itStoresStateInSessionHandler()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->expects($this->once())
            ->method('set')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE), $this->anything());

        $handler = new StateNonceHandler($sessionDataHandler);
        $handler->generateState();
    }

    /**
     * @test
     */
    public function itStoresNonceInSessionHandler()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->expects($this->once())
            ->method('set')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE), $this->anything());

        $handler = new StateNonceHandler($sessionDataHandler);
        $handler->generateNonce();
    }

    /**
     * @test
     */
    public function itFailsStateValidationWhenStateIsNotSet()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE))
            ->willReturn(null);

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertFalse($handler->validateState('any state'));
    }

    /**
     * @test
     */
    public function itFailsStateValidationWhenSetStateDiffers()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE))
            ->willReturn('old state');

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertFalse($handler->validateState('new state'));
    }

    /**
     * @test
     */
    public function itPassesStateValidationIfStoredAndReceivedStatesAreEqual()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE))
            ->willReturn('the set state');

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertTrue($handler->validateState('the set state'));
    }

    /**
     * @test
     */
    public function itClearsSetStateAfterPassingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE))
            ->willReturn('the set state');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE));

        (new StateNonceHandler($sessionDataHandler))->validateState('the set state');
    }

    /**
     * @test
     */
    public function itPreservesStateAfterFailingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE))
            ->willReturn('the set state');

        $sessionDataHandler->expects($this->never())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE));

        (new StateNonceHandler($sessionDataHandler))->validateState('different state');
    }

    /**
     * @test
     */
    public function itFailsNonceValidationWhenNonceIsNotSet()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn(null);

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertFalse($handler->validateNonce('any nonce'));
    }

    /**
     * @test
     */
    public function itFailsNonceValidationWhenSetNonceDiffers()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('old nonce');

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertFalse($handler->validateNonce('new nonce'));
    }

    /**
     * @test
     */
    public function itPassesNonceValidationIfStoredAndReceivedNoncesAreEqual()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->expects($this->once())
            ->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('the set nonce');

        $handler = new StateNonceHandler($sessionDataHandler);
        $this->assertTrue($handler->validateNonce('the set nonce'));
    }

    /**
     * @test
     */
    public function itClearsSetNonceAfterPassingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('the set nonce');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE));

        (new StateNonceHandler($sessionDataHandler))->validateNonce('the set nonce');
    }

    /**
     * @test
     */
    public function itPreservesNonceAfterFailingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('the set nonce');

        $sessionDataHandler->expects($this->never())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE));

        (new StateNonceHandler($sessionDataHandler))->validateNonce('different nonce');
    }
}
