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

        $handler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
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

        $handler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
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

        $handler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
        $this->assertFalse($handler->validateState('1234567890123456789012'));
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
            ->willReturn('a234567890123456789012');

        $handler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
        $this->assertFalse($handler->validateState('b234567890123456789012'));
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
            ->willReturn('1234567890123456789012');

        $handler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
        $this->assertTrue($handler->validateState('1234567890123456789012'));
    }

    /**
     * @test
     */
    public function itClearsSetStateAfterPassingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE))
            ->willReturn('1234567890123456789012');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE));

        (new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse()))
            ->validateState('1234567890123456789012');
    }

    /**
     * @test
     */
    public function itClearsSetStateAfterFailingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE))
            ->willReturn('a234567890123456789012');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_STATE));

        (new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse()))
            ->validateState('b234567890123456789012');
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

        $handler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
        $this->assertFalse($handler->validateNonce('1234567890123456789012', 'dummy-client-secret', 0, 0));
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
            ->willReturn('a234567890123456789012');

        $handler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
        $this->assertFalse($handler->validateNonce('b234567890123456789012', 'dummy-client-secret', 0, 0));
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
            ->willReturn('1234567890123456789012');

        $handler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
        $this->assertTrue($handler->validateNonce('1234567890123456789012', 'dummy-client-secret', 0, 0));
    }

    /**
     * @test
     */
    public function itPassesNonceValidationIfValidTotpNonceIsUsedInNormalMode1()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('anything');


        $handler = new StateNonceHandler($sessionDataHandler, new TotpValidator());

        $this->assertTrue(
            $handler->validateNonce(
                'oK6myPegbmYRdXd2V10nv+ZWEnk=N',
                'qQmvC2yRr7QoAdISoEG1r9IAyjRe7zmh0QlFlPBNUO0=',
                1500902310,
                0));
    }

    /**
     * @test
     */
    public function itPassesNonceValidationIfValidTotpNonceIsUsedInConvenientMode1()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('anything');

        $handler = new StateNonceHandler($sessionDataHandler, new TotpValidator());

        $this->assertTrue(
            $handler->validateNonce(
                'oK6myPegbmYRdXd2V10nv+ZWEnk=C',
                'qQmvC2yRr7QoAdISoEG1r9IAyjRe7zmh0QlFlPBNUO0=',
                0,
                1500902349));
    }

        /**
     * @test
     */
    public function itPassesNonceValidationIfValidTotpNonceIsUsedInConvenientMode2()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('anything');

        $handler = new StateNonceHandler($sessionDataHandler, new TotpValidator());

        $this->assertTrue(
            $handler->validateNonce(
                'oK6myPegbmYRdXd2V10nv+ZWEnk=C',
                'qQmvC2yRr7QoAdISoEG1r9IAyjRe7zmh0QlFlPBNUO0=',
                0,
                1500902310));
    }

    /**
     * @test
     */
    public function itPassesNonceValidationIfValidTotpNonceIsUsedInNormalMode2()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('anything');

        $handler = new StateNonceHandler($sessionDataHandler, new TotpValidator());

        $this->assertTrue(
            $handler->validateNonce(
                'oK6myPegbmYRdXd2V10nv+ZWEnk=N',
                'qQmvC2yRr7QoAdISoEG1r9IAyjRe7zmh0QlFlPBNUO0=',
                1500902349,
                0));
    }


    /**
     * @test
     */
    public function itFailsNonceValidationIfInvalidTotpNonceIsUsedInNormalMode()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('anything');

        $handler = new StateNonceHandler($sessionDataHandler, new TotpValidator());

        $this->assertFalse(
            $handler->validateNonce(
                'oK6myPegbmYRdXd2V10nv+ZWEnk=N',
                'qQmvC2yRr7QoAdISoEG1r9IAyjRe7zmh0QlFlPBNUO0=',
                1500902309,
                0));
    }

        /**
     * @test
     */
    public function itFailsNonceValidationIfInvalidTotpNonceIsUsedInConvenientMode()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('anything');

        $handler = new StateNonceHandler($sessionDataHandler, new TotpValidator());

        $this->assertFalse(
            $handler->validateNonce(
                'oK6myPegbmYRdXd2V10nv+ZWEnk=C',
                'qQmvC2yRr7QoAdISoEG1r9IAyjRe7zmh0QlFlPBNUO0=',
                0,
                1500902350));
    }


    /**
     * @test
     */
    public function itClearsSetNonceAfterPassingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('1234567890123456789012');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE));

        (new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse()))
            ->validateNonce('1234567890123456789012', 'dummy-client-secret', 0, 0);
    }

    /**
     * @test
     */
    public function itClearsSetNonceAfterFailingValidation()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn('a234567890123456789012');

        $sessionDataHandler->expects($this->once())
            ->method('remove')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE));

        (new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse()))
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
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn(null);

        (new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse()))
            ->validateNonce('123456789012345678901', 'dummy-client-secret', 0, 0);
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid nonce validation mode
     */
    public function itThrowsOnBadTotpNonceValidationMode()
    {
        $sessionDataHandler = $this->createMock(SessionDataHandler::class);
        $sessionDataHandler->method('get')
            ->with($this->equalTo(SessionDataHandler::SESSION_KEY_NONCE))
            ->willReturn(null);

        $stateNonceHandler = new StateNonceHandler($sessionDataHandler, $this->createTotpValidatorReturningFalse());
        $stateNonceHandler->validateNonce(
                'oK6myPegbmYRdXd2V10nv+ZWEnk=x',
                'qQmvC2yRr7QoAdISoEG1r9IAyjRe7zmh0QlFlPBNUO0=',
                0,
                1500902310);
    }

    /**
     *
     * @return TotpValidator
     */
    private function createTotpValidatorReturningFalse()
    {
        $totpValidator = $this->createMock(TotpValidator::class);
        $totpValidator->method('isValid')
            ->willReturn(false);

        return $totpValidator;
    }
}
