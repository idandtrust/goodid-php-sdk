<?php

namespace GoodID\Helpers\Response;

use Jose\Component\Core\JWKSet;

class TokenExtractorTest extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        $this->markTestIncomplete();
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported input
     */
    public function itThrowsWhenInputIsNotAJWS()
    {
        $cut = new TokenExtractor(new JWKSet(), new JWKSet());
        $cut->extractToken('invalid string');
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to decode
     */
    public function itThrowsWhenJWSHeaderIsInvalid()
    {
        $cut = new TokenExtractor(new JWKSet(), new JWKSet());
        $cut->extractToken('AAA.AAA.AAA');
    }

    /**
     * Previous Jose lib version will raise a fatal error when the protected header can not be decoded to an array;
     * this is a Good Thing (tm), but unfortunately makes this test fail on php 5.6
     *
     * @requires PHP 7
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to decode JWE
     */
    public function itThrowsWhenJWEHeaderIsInvalid()
    {
        $cut = new TokenExtractor(new JWKSet(), new JWKSet());
        $cut->extractToken('AAA.AAA.AAA.AAA.AAA');
    }

    /**
     * @test
     */
    public function itExtractsJWS()
    {
        $cut = new TokenExtractor(
            new JWKSet(),
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'x' => 'h72PwAzJdnNUnTfvubnn0T0HFV9Wyofo23nfERxw9gM',
                        'y' => 'Z1lmCtUhoFuPAqGxkxSCQNe4UKdlD1GU0TzDgG4sJfk',
                    ]
                ]
            ])
        );
        $jwt = $cut->extractToken('eyJhbGciOiJFUzI1NiIsImtpZCI6InlmTHprRGYxaGZndHBDRXZqVVQ2bm4zR2s5TkF6Z0U0T0FBV1dKRF9oUU0ifQ.eyJjbGFpbSI6InZhbHVlIn0.PNEr2R9bNvdfI9zIxoYKZcGarCTgvKiAh4wVs0BgXwItBPCa--JrW3xJw5_WhfxxkbU_K2LjhCA_jIGaICSdzw');
        $this->assertEquals(['claim' => 'value'], $jwt->getClaims());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to verify
     */
    public function itVerifiesJWS()
    {
        $cut = new TokenExtractor(
            new JWKSet(),
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'x' => 'x000000000000000000000000000000000000000000',
                        'y' => 'y000000000000000000000000000000000000000000',
                    ]
                ]
            ])
        );
        $jwt = $cut->extractToken('eyJhbGciOiJFUzI1NiIsImtpZCI6InlmTHprRGYxaGZndHBDRXZqVVQ2bm4zR2s5TkF6Z0U0T0FBV1dKRF9oUU0ifQ.eyJjbGFpbSI6InZhbHVlIn0.PNEr2R9bNvdfI9zIxoYKZcGarCTgvKiAh4wVs0BgXwItBPCa--JrW3xJw5_WhfxxkbU_K2LjhCA_jIGaICSdzw');
        $this->assertEquals(['claim' => 'value'], $jwt->getClaims());
    }

    /**
     * @test
     */
    public function itExtractsJWE()
    {
        $cut = new TokenExtractor(
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'n' => '4cagIQBAMGVRQczExA3eX9TBdAG78tKU5TFWUn7XzHmhnXEJpuNvg_14v8u8RRW6MG9FlBobVgvn2WvDO3WvZuNw3xOuPWJTjRFozqAOyn2CxQvmMJ8FFpBN7xFc6EMVCMEH-BZG5kZaIl0FxMYJRL64nIyIoyBQ_oYBU-MHN17F2sahfL66LPw7nH0KZxLFGWZcG3NKeJ74mFe9oI1z5SAzNtklE5tURYVI_GHjzrB5-5BBDzQMNOh8GJhKtBcTQu6HiMqMa2GbDS22bdx5CD9-f6xJGEohxFwAmvD188nNlnnUHC6nqn1oGI3uqbAuDe9ManncbbvQd8-bq5N4xQ',
                        'e' => 'AQAB',
                        'd' => 's205xuA_Ivbx-7vzR-fJqRkY4MucBV8LS5XJB2icsXicUtYJmKK49glTlAEizzh0LpfPkOKqhNiTWfvFPRTK35azFeW7HDdvNPX39_XFq3DRoy1Qs6U80vC9rtd6oW7mYX2eiq-RiuGwMg0BT58esI5tgqRA1nsRQyVWGsea7YmaRVbeYL06ytWc4rsBBBBr3AFV6bHqX6uwyh7ZhKwCd9xZiO0AWzrdPFo3GQDfOvR8Q4sYk2k7Bs6bmVA58sTo8srxU1PB77Eb8Bg79AVyc3GnKXp43HEfNttqiluxj8G3632pEOeeo9PI1WvqEQwnGEzZZv8xlCuqmcTKYN9VBQ',
                        'p' => '_XT4VM-Jh_tKtnG43QONVFf4WVheAjCX_CoDqo9k2Xf-6hW-5JlF6btXfmjlupvsaq40pkF2ubeW1RXIbayVwlvwbD39uiivh8LhgvDVFWdf3DdAMKj3O73cTaU-0vd6-PVxxJpimsCEjcrFZdMnmUDtTJBDA9egnDaZR8DAuxM',
                        'q' => '5AqNzF8Ou1Vrlm__dg4htzffAKX52aB0945VUJzs78FeP1EwxuiG8xf55iUCqkNnwq7z8R9aXdu3v-RsBN4GtPuZCLxhfvb9sW6Pt207-FHSRrioj5rlviXxgR7TSlCm5Lmyu_1Sw7HIsyw0Jq-ak0FU-tWvM9X5PG-7o1MSX8c',
                        'dp' => 'Nf8XcKoOOMQWdKvhoGRDVbawGAi1bm3_0x74TPvjllj0G9aqJnVo6ZSZ3Tpnxsu1ID0gxlKoAoTUQ20yl_rupMuFeunyBhjo3FluRcEdBERTrcyvhi5ZDYczSe9sZPGIZ0WTCTmCzEk7dCHA0CKeCw5D_820GTt04hLXsOulo7U',
                        'dq' => 'MrNyAW1lDhuY1xLBnpLXxi-i4jcEzPES8HNx3oF1YH0Cols_2Amc73F2O0ghRo_EAxH45LRO2C1gtkZoCdD_dr-1r66KkrsBfrCRPXwI6FXwxY6K05rh15wCDO44lf5GjPYImilhfGcLs2JxmeRTHshYx4g48vJw_pHtCwwOOsM',
                        'qi' => 'Ey9cXGlGbA2j5bO3l_JyPs43myTyqKfm6F6TMVeJi0lF0ypUS6KAMLZYHzaQg112FatsYS-OTWgcZBHbN745cI_Aq5-d63jSUlm9LxMycKFI0CAjn-8Q_H7Y_DbhLzH-0dQTticfzKFgCKKZmIVHzoHv6dSOwMSaYaWaMlh7uwo'
                    ]
                ]
            ]),
            new JWKSet()
        );
        $jwt = $cut->extractToken('eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJ0eXB1WWdlX0phWVVDeVl4ZmxYV1doTDZnZWRqdEZtQm10S1pFdm94U1hJIn0.p3imv-ScjY0BGcDrHrmFsM7SUEWc5guELp1Ic6wiK036YBeSViL_t1RSKk6u_CDpOQbiI_k-_C2AnkI2WA-8HOJH_xqEkbTSkfmZYy2gJ8Z9bfImKVJy6rSLtZej8fIstVwnGTPp7F9pJ2iu2bONtOW-EjGtG3PfVpNE6i3jhZumKMJC7HqSKSq2MgpCzVyAsN6fTd6XZgReENCVv6HMIqj6eti5eJ6smcFvmPhlBNtNycltlkgL7zCaLFSd7PRhaEz6QJ9guRrxnobhZ4nJqGqV8UGOsCb4VtOQCIot9WNLTsMUe2XOuAqhRzBU5qpXz01uYjYihjfEIcfqG5IFXw.GOxKuuW8od1LoM-UrjiKRA.sbhAVkfobQyjjCWqWQ2344U8R-gPwIYZ3kxLrd2EhL8.KcXU7Xl_9ZkqnvZEeKsGoQ');
        $this->assertEquals(['claim' => 'value'], $jwt->getClaims());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to decrypt
     */
    public function itThrowsWhenNoKeyFoundForDecrypt()
    {
        $cut = new TokenExtractor(
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'n' => '4cagIQBAMGVRQczExA3eX9TBdAG78tKU5TFWUn7XzHmhnXEJpuNvg_14v8u8RRW6MG9FlBobVgvn2WvDO3WvZuNw3xOuPWJTjRFozqAOyn2CxQvmMJ8FFpBN7xFc6EMVCMEH-BZG5kZaIl0FxMYJRL64nIyIoyBQ_oYBU-MHN17F2sahfL66LPw7nH0KZxLFGWZcG3NKeJ74mFe9oI1z5SAzNtklE5tURYVI_GHjzrB5-5BBDzQMNOh8GJhKtBcTQu6HiMqMa2GbDS22bdx5CD9-f6xJGEohxFwAmvD188nNlnnUHC6nqn1oGI3uqbAuDe9ManncbbvQd8-bq5N4xQ',
                        'e' => 'AQAB',
                        'd' => 'd',
                        'p' => '_XT4VM-Jh_tKtnG43QONVFf4WVheAjCX_CoDqo9k2Xf-6hW-5JlF6btXfmjlupvsaq40pkF2ubeW1RXIbayVwlvwbD39uiivh8LhgvDVFWdf3DdAMKj3O73cTaU-0vd6-PVxxJpimsCEjcrFZdMnmUDtTJBDA9egnDaZR8DAuxM',
                        'q' => '5AqNzF8Ou1Vrlm__dg4htzffAKX52aB0945VUJzs78FeP1EwxuiG8xf55iUCqkNnwq7z8R9aXdu3v-RsBN4GtPuZCLxhfvb9sW6Pt207-FHSRrioj5rlviXxgR7TSlCm5Lmyu_1Sw7HIsyw0Jq-ak0FU-tWvM9X5PG-7o1MSX8c',
                        'dp' => 'Nf8XcKoOOMQWdKvhoGRDVbawGAi1bm3_0x74TPvjllj0G9aqJnVo6ZSZ3Tpnxsu1ID0gxlKoAoTUQ20yl_rupMuFeunyBhjo3FluRcEdBERTrcyvhi5ZDYczSe9sZPGIZ0WTCTmCzEk7dCHA0CKeCw5D_820GTt04hLXsOulo7U',
                        'dq' => 'MrNyAW1lDhuY1xLBnpLXxi-i4jcEzPES8HNx3oF1YH0Cols_2Amc73F2O0ghRo_EAxH45LRO2C1gtkZoCdD_dr-1r66KkrsBfrCRPXwI6FXwxY6K05rh15wCDO44lf5GjPYImilhfGcLs2JxmeRTHshYx4g48vJw_pHtCwwOOsM',
                        'qi' => 'Ey9cXGlGbA2j5bO3l_JyPs43myTyqKfm6F6TMVeJi0lF0ypUS6KAMLZYHzaQg112FatsYS-OTWgcZBHbN745cI_Aq5-d63jSUlm9LxMycKFI0CAjn-8Q_H7Y_DbhLzH-0dQTticfzKFgCKKZmIVHzoHv6dSOwMSaYaWaMlh7uwo'
                    ]
                ]
            ]),
            new JWKSet()
        );
        $jwt = $cut->extractToken('eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJ0eXB1WWdlX0phWVVDeVl4ZmxYV1doTDZnZWRqdEZtQm10S1pFdm94U1hJIn0.p3imv-ScjY0BGcDrHrmFsM7SUEWc5guELp1Ic6wiK036YBeSViL_t1RSKk6u_CDpOQbiI_k-_C2AnkI2WA-8HOJH_xqEkbTSkfmZYy2gJ8Z9bfImKVJy6rSLtZej8fIstVwnGTPp7F9pJ2iu2bONtOW-EjGtG3PfVpNE6i3jhZumKMJC7HqSKSq2MgpCzVyAsN6fTd6XZgReENCVv6HMIqj6eti5eJ6smcFvmPhlBNtNycltlkgL7zCaLFSd7PRhaEz6QJ9guRrxnobhZ4nJqGqV8UGOsCb4VtOQCIot9WNLTsMUe2XOuAqhRzBU5qpXz01uYjYihjfEIcfqG5IFXw.GOxKuuW8od1LoM-UrjiKRA.sbhAVkfobQyjjCWqWQ2344U8R-gPwIYZ3kxLrd2EhL8.KcXU7Xl_9ZkqnvZEeKsGoQ');
    }

    /**
     * @test
     */
    public function itDecryptsAndVerifiesJWEWithJWSPayload()
    {
        $cut = new TokenExtractor(
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'n' => '4cagIQBAMGVRQczExA3eX9TBdAG78tKU5TFWUn7XzHmhnXEJpuNvg_14v8u8RRW6MG9FlBobVgvn2WvDO3WvZuNw3xOuPWJTjRFozqAOyn2CxQvmMJ8FFpBN7xFc6EMVCMEH-BZG5kZaIl0FxMYJRL64nIyIoyBQ_oYBU-MHN17F2sahfL66LPw7nH0KZxLFGWZcG3NKeJ74mFe9oI1z5SAzNtklE5tURYVI_GHjzrB5-5BBDzQMNOh8GJhKtBcTQu6HiMqMa2GbDS22bdx5CD9-f6xJGEohxFwAmvD188nNlnnUHC6nqn1oGI3uqbAuDe9ManncbbvQd8-bq5N4xQ',
                        'e' => 'AQAB',
                        'd' => 's205xuA_Ivbx-7vzR-fJqRkY4MucBV8LS5XJB2icsXicUtYJmKK49glTlAEizzh0LpfPkOKqhNiTWfvFPRTK35azFeW7HDdvNPX39_XFq3DRoy1Qs6U80vC9rtd6oW7mYX2eiq-RiuGwMg0BT58esI5tgqRA1nsRQyVWGsea7YmaRVbeYL06ytWc4rsBBBBr3AFV6bHqX6uwyh7ZhKwCd9xZiO0AWzrdPFo3GQDfOvR8Q4sYk2k7Bs6bmVA58sTo8srxU1PB77Eb8Bg79AVyc3GnKXp43HEfNttqiluxj8G3632pEOeeo9PI1WvqEQwnGEzZZv8xlCuqmcTKYN9VBQ',
                        'p' => '_XT4VM-Jh_tKtnG43QONVFf4WVheAjCX_CoDqo9k2Xf-6hW-5JlF6btXfmjlupvsaq40pkF2ubeW1RXIbayVwlvwbD39uiivh8LhgvDVFWdf3DdAMKj3O73cTaU-0vd6-PVxxJpimsCEjcrFZdMnmUDtTJBDA9egnDaZR8DAuxM',
                        'q' => '5AqNzF8Ou1Vrlm__dg4htzffAKX52aB0945VUJzs78FeP1EwxuiG8xf55iUCqkNnwq7z8R9aXdu3v-RsBN4GtPuZCLxhfvb9sW6Pt207-FHSRrioj5rlviXxgR7TSlCm5Lmyu_1Sw7HIsyw0Jq-ak0FU-tWvM9X5PG-7o1MSX8c',
                        'dp' => 'Nf8XcKoOOMQWdKvhoGRDVbawGAi1bm3_0x74TPvjllj0G9aqJnVo6ZSZ3Tpnxsu1ID0gxlKoAoTUQ20yl_rupMuFeunyBhjo3FluRcEdBERTrcyvhi5ZDYczSe9sZPGIZ0WTCTmCzEk7dCHA0CKeCw5D_820GTt04hLXsOulo7U',
                        'dq' => 'MrNyAW1lDhuY1xLBnpLXxi-i4jcEzPES8HNx3oF1YH0Cols_2Amc73F2O0ghRo_EAxH45LRO2C1gtkZoCdD_dr-1r66KkrsBfrCRPXwI6FXwxY6K05rh15wCDO44lf5GjPYImilhfGcLs2JxmeRTHshYx4g48vJw_pHtCwwOOsM',
                        'qi' => 'Ey9cXGlGbA2j5bO3l_JyPs43myTyqKfm6F6TMVeJi0lF0ypUS6KAMLZYHzaQg112FatsYS-OTWgcZBHbN745cI_Aq5-d63jSUlm9LxMycKFI0CAjn-8Q_H7Y_DbhLzH-0dQTticfzKFgCKKZmIVHzoHv6dSOwMSaYaWaMlh7uwo'
                    ]
                ]
            ]),
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'x' => 'h72PwAzJdnNUnTfvubnn0T0HFV9Wyofo23nfERxw9gM',
                        'y' => 'Z1lmCtUhoFuPAqGxkxSCQNe4UKdlD1GU0TzDgG4sJfk',
                    ]
                ]
            ])
        );
        $jwt = $cut->extractToken('eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJ0eXB1WWdlX0phWVVDeVl4ZmxYV1doTDZnZWRqdEZtQm10S1pFdm94U1hJIn0.buX8RushyLFmKz6K_o5zqJjUHVJeOgg_1VTw8XH69QMFKrHN7ho0FlcN5C1vrEQmw9O-K8jYbyQ_01UTyfqMYIq8cJiSvOsaPF7waXC8dwOd4hVltoE2vUrkTpnYbm90iCiTjhjBTTrU2lVh1fKzl329re1jiUENOUe5cEFiDcOZ-5xpnvZfENAOZ2shvNrZ_iKWxRkR9CJvQUajtoY0Uvk-ptDX6UbgObtqPYVR1EBVcedQ1UV1VQ-IBQoNffUSStj1oqHEk21SYgiHUNgkSIXZMUtC_JJ28CS-WJkcAKFdv8oiTtKJGnnhGXR2uqNFXUAQ7-Fzg506gKX7RI_tIg.xZjI-teBFP8iJ42auw1reA.E3e-8ySnrT5fRkWn0cVqSkEBh7Cb-al513ODCp-IGuuaHXQZfOV37M1P6CXZEfJcobMWplxJj7AdPIwjfT3IuIjOIXDvOJPFdnfcHyFbFu1sjwuED2P0NSXJn0trdh1VUpv1Cg93XK4O5JyvHTW0EpnXcV-NbDfGiCwNCY4U6ci29OUI-TTQjiqeiBgGs2c3Dxlw2sh8bzK3rG4OdKupp_dTNnTcivneVgOk0CaVearEB0AuXDmneXm4z99o1M49Kb8oxg50WknRXibcFpGfvg.az7DDll6dsWkaBoaLFYAoQ');
        $this->assertEquals(['claim' => 'value'], $jwt->getClaims());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to verify
     */
    public function itThrowsIfDecryptedJWSHasInvalidSignature()
    {
        $cut = new TokenExtractor(
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'n' => '4cagIQBAMGVRQczExA3eX9TBdAG78tKU5TFWUn7XzHmhnXEJpuNvg_14v8u8RRW6MG9FlBobVgvn2WvDO3WvZuNw3xOuPWJTjRFozqAOyn2CxQvmMJ8FFpBN7xFc6EMVCMEH-BZG5kZaIl0FxMYJRL64nIyIoyBQ_oYBU-MHN17F2sahfL66LPw7nH0KZxLFGWZcG3NKeJ74mFe9oI1z5SAzNtklE5tURYVI_GHjzrB5-5BBDzQMNOh8GJhKtBcTQu6HiMqMa2GbDS22bdx5CD9-f6xJGEohxFwAmvD188nNlnnUHC6nqn1oGI3uqbAuDe9ManncbbvQd8-bq5N4xQ',
                        'e' => 'AQAB',
                        'd' => 's205xuA_Ivbx-7vzR-fJqRkY4MucBV8LS5XJB2icsXicUtYJmKK49glTlAEizzh0LpfPkOKqhNiTWfvFPRTK35azFeW7HDdvNPX39_XFq3DRoy1Qs6U80vC9rtd6oW7mYX2eiq-RiuGwMg0BT58esI5tgqRA1nsRQyVWGsea7YmaRVbeYL06ytWc4rsBBBBr3AFV6bHqX6uwyh7ZhKwCd9xZiO0AWzrdPFo3GQDfOvR8Q4sYk2k7Bs6bmVA58sTo8srxU1PB77Eb8Bg79AVyc3GnKXp43HEfNttqiluxj8G3632pEOeeo9PI1WvqEQwnGEzZZv8xlCuqmcTKYN9VBQ',
                        'p' => '_XT4VM-Jh_tKtnG43QONVFf4WVheAjCX_CoDqo9k2Xf-6hW-5JlF6btXfmjlupvsaq40pkF2ubeW1RXIbayVwlvwbD39uiivh8LhgvDVFWdf3DdAMKj3O73cTaU-0vd6-PVxxJpimsCEjcrFZdMnmUDtTJBDA9egnDaZR8DAuxM',
                        'q' => '5AqNzF8Ou1Vrlm__dg4htzffAKX52aB0945VUJzs78FeP1EwxuiG8xf55iUCqkNnwq7z8R9aXdu3v-RsBN4GtPuZCLxhfvb9sW6Pt207-FHSRrioj5rlviXxgR7TSlCm5Lmyu_1Sw7HIsyw0Jq-ak0FU-tWvM9X5PG-7o1MSX8c',
                        'dp' => 'Nf8XcKoOOMQWdKvhoGRDVbawGAi1bm3_0x74TPvjllj0G9aqJnVo6ZSZ3Tpnxsu1ID0gxlKoAoTUQ20yl_rupMuFeunyBhjo3FluRcEdBERTrcyvhi5ZDYczSe9sZPGIZ0WTCTmCzEk7dCHA0CKeCw5D_820GTt04hLXsOulo7U',
                        'dq' => 'MrNyAW1lDhuY1xLBnpLXxi-i4jcEzPES8HNx3oF1YH0Cols_2Amc73F2O0ghRo_EAxH45LRO2C1gtkZoCdD_dr-1r66KkrsBfrCRPXwI6FXwxY6K05rh15wCDO44lf5GjPYImilhfGcLs2JxmeRTHshYx4g48vJw_pHtCwwOOsM',
                        'qi' => 'Ey9cXGlGbA2j5bO3l_JyPs43myTyqKfm6F6TMVeJi0lF0ypUS6KAMLZYHzaQg112FatsYS-OTWgcZBHbN745cI_Aq5-d63jSUlm9LxMycKFI0CAjn-8Q_H7Y_DbhLzH-0dQTticfzKFgCKKZmIVHzoHv6dSOwMSaYaWaMlh7uwo'
                    ]
                ]
            ]),
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'x' => 'x000000000000000000000000000000000000000000',
                        'y' => 'y000000000000000000000000000000000000000000',
                    ]
                ]
            ])
        );
        $jwt = $cut->extractToken('eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJ0eXB1WWdlX0phWVVDeVl4ZmxYV1doTDZnZWRqdEZtQm10S1pFdm94U1hJIn0.buX8RushyLFmKz6K_o5zqJjUHVJeOgg_1VTw8XH69QMFKrHN7ho0FlcN5C1vrEQmw9O-K8jYbyQ_01UTyfqMYIq8cJiSvOsaPF7waXC8dwOd4hVltoE2vUrkTpnYbm90iCiTjhjBTTrU2lVh1fKzl329re1jiUENOUe5cEFiDcOZ-5xpnvZfENAOZ2shvNrZ_iKWxRkR9CJvQUajtoY0Uvk-ptDX6UbgObtqPYVR1EBVcedQ1UV1VQ-IBQoNffUSStj1oqHEk21SYgiHUNgkSIXZMUtC_JJ28CS-WJkcAKFdv8oiTtKJGnnhGXR2uqNFXUAQ7-Fzg506gKX7RI_tIg.xZjI-teBFP8iJ42auw1reA.E3e-8ySnrT5fRkWn0cVqSkEBh7Cb-al513ODCp-IGuuaHXQZfOV37M1P6CXZEfJcobMWplxJj7AdPIwjfT3IuIjOIXDvOJPFdnfcHyFbFu1sjwuED2P0NSXJn0trdh1VUpv1Cg93XK4O5JyvHTW0EpnXcV-NbDfGiCwNCY4U6ci29OUI-TTQjiqeiBgGs2c3Dxlw2sh8bzK3rG4OdKupp_dTNnTcivneVgOk0CaVearEB0AuXDmneXm4z99o1M49Kb8oxg50WknRXibcFpGfvg.az7DDll6dsWkaBoaLFYAoQ');
        $this->assertEquals(['claim' => 'value'], $jwt->getClaims());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to decode
     */
    public function itThrowsWhenDecryptedJWSIsInvalid()
    {
        $cut = new TokenExtractor(
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'n' => '4cagIQBAMGVRQczExA3eX9TBdAG78tKU5TFWUn7XzHmhnXEJpuNvg_14v8u8RRW6MG9FlBobVgvn2WvDO3WvZuNw3xOuPWJTjRFozqAOyn2CxQvmMJ8FFpBN7xFc6EMVCMEH-BZG5kZaIl0FxMYJRL64nIyIoyBQ_oYBU-MHN17F2sahfL66LPw7nH0KZxLFGWZcG3NKeJ74mFe9oI1z5SAzNtklE5tURYVI_GHjzrB5-5BBDzQMNOh8GJhKtBcTQu6HiMqMa2GbDS22bdx5CD9-f6xJGEohxFwAmvD188nNlnnUHC6nqn1oGI3uqbAuDe9ManncbbvQd8-bq5N4xQ',
                        'e' => 'AQAB',
                        'd' => 's205xuA_Ivbx-7vzR-fJqRkY4MucBV8LS5XJB2icsXicUtYJmKK49glTlAEizzh0LpfPkOKqhNiTWfvFPRTK35azFeW7HDdvNPX39_XFq3DRoy1Qs6U80vC9rtd6oW7mYX2eiq-RiuGwMg0BT58esI5tgqRA1nsRQyVWGsea7YmaRVbeYL06ytWc4rsBBBBr3AFV6bHqX6uwyh7ZhKwCd9xZiO0AWzrdPFo3GQDfOvR8Q4sYk2k7Bs6bmVA58sTo8srxU1PB77Eb8Bg79AVyc3GnKXp43HEfNttqiluxj8G3632pEOeeo9PI1WvqEQwnGEzZZv8xlCuqmcTKYN9VBQ',
                        'p' => '_XT4VM-Jh_tKtnG43QONVFf4WVheAjCX_CoDqo9k2Xf-6hW-5JlF6btXfmjlupvsaq40pkF2ubeW1RXIbayVwlvwbD39uiivh8LhgvDVFWdf3DdAMKj3O73cTaU-0vd6-PVxxJpimsCEjcrFZdMnmUDtTJBDA9egnDaZR8DAuxM',
                        'q' => '5AqNzF8Ou1Vrlm__dg4htzffAKX52aB0945VUJzs78FeP1EwxuiG8xf55iUCqkNnwq7z8R9aXdu3v-RsBN4GtPuZCLxhfvb9sW6Pt207-FHSRrioj5rlviXxgR7TSlCm5Lmyu_1Sw7HIsyw0Jq-ak0FU-tWvM9X5PG-7o1MSX8c',
                        'dp' => 'Nf8XcKoOOMQWdKvhoGRDVbawGAi1bm3_0x74TPvjllj0G9aqJnVo6ZSZ3Tpnxsu1ID0gxlKoAoTUQ20yl_rupMuFeunyBhjo3FluRcEdBERTrcyvhi5ZDYczSe9sZPGIZ0WTCTmCzEk7dCHA0CKeCw5D_820GTt04hLXsOulo7U',
                        'dq' => 'MrNyAW1lDhuY1xLBnpLXxi-i4jcEzPES8HNx3oF1YH0Cols_2Amc73F2O0ghRo_EAxH45LRO2C1gtkZoCdD_dr-1r66KkrsBfrCRPXwI6FXwxY6K05rh15wCDO44lf5GjPYImilhfGcLs2JxmeRTHshYx4g48vJw_pHtCwwOOsM',
                        'qi' => 'Ey9cXGlGbA2j5bO3l_JyPs43myTyqKfm6F6TMVeJi0lF0ypUS6KAMLZYHzaQg112FatsYS-OTWgcZBHbN745cI_Aq5-d63jSUlm9LxMycKFI0CAjn-8Q_H7Y_DbhLzH-0dQTticfzKFgCKKZmIVHzoHv6dSOwMSaYaWaMlh7uwo'
                    ]
                ]
            ]),
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'x' => 'h72PwAzJdnNUnTfvubnn0T0HFV9Wyofo23nfERxw9gM',
                        'y' => 'Z1lmCtUhoFuPAqGxkxSCQNe4UKdlD1GU0TzDgG4sJfk',
                    ]
                ]
            ])
        );

        $cut->extractToken('eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJ0eXB1WWdlX0phWVVDeVl4ZmxYV1doTDZnZWRqdEZtQm10S1pFdm94U1hJIn0.IloLnSIoDOf9l_wHC3uO2x_93H2vfqyxZ8FMzVdj3fqDrd3muXvFshaFP0LI4qp_-N3PUe2z6tcs8GElQ8QStZf-4J1z3anJB0HpuPQpCbuaV0eP-NAOeYcpZy17XqJoNhtQ5t9H3duTn-9maNnOzELvRgtH7zSeABFQagAmAk-jzaxhXeFHXrOytQhBY0WVxDjJSfnd5Tpi8zmG-qSRmp34CvEGIe133Ld6_fyz2WpLcnMNrtUQV5LRurSjm7eURfR_wOUMLuBBWkESVI0P3La4cIVKxLBaE2oeMThrmbISeCujMRjtwJ86s_qABFb2hgkRU-pg0b8SVjj16JxBQg.ApEysaWzRIJfNhUrbjhMaQ.IlM1P6MlIsmnQ5uLD4sUQA.sHY8mW_DNoLo6ITDUQfP8A');
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The token does not seem to contain a JWS
     */
    public function itThrowsWhenDecryptedDataIsNotAJWS()
    {
        $cut = new TokenExtractor(
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'n' => '4cagIQBAMGVRQczExA3eX9TBdAG78tKU5TFWUn7XzHmhnXEJpuNvg_14v8u8RRW6MG9FlBobVgvn2WvDO3WvZuNw3xOuPWJTjRFozqAOyn2CxQvmMJ8FFpBN7xFc6EMVCMEH-BZG5kZaIl0FxMYJRL64nIyIoyBQ_oYBU-MHN17F2sahfL66LPw7nH0KZxLFGWZcG3NKeJ74mFe9oI1z5SAzNtklE5tURYVI_GHjzrB5-5BBDzQMNOh8GJhKtBcTQu6HiMqMa2GbDS22bdx5CD9-f6xJGEohxFwAmvD188nNlnnUHC6nqn1oGI3uqbAuDe9ManncbbvQd8-bq5N4xQ',
                        'e' => 'AQAB',
                        'd' => 's205xuA_Ivbx-7vzR-fJqRkY4MucBV8LS5XJB2icsXicUtYJmKK49glTlAEizzh0LpfPkOKqhNiTWfvFPRTK35azFeW7HDdvNPX39_XFq3DRoy1Qs6U80vC9rtd6oW7mYX2eiq-RiuGwMg0BT58esI5tgqRA1nsRQyVWGsea7YmaRVbeYL06ytWc4rsBBBBr3AFV6bHqX6uwyh7ZhKwCd9xZiO0AWzrdPFo3GQDfOvR8Q4sYk2k7Bs6bmVA58sTo8srxU1PB77Eb8Bg79AVyc3GnKXp43HEfNttqiluxj8G3632pEOeeo9PI1WvqEQwnGEzZZv8xlCuqmcTKYN9VBQ',
                        'p' => '_XT4VM-Jh_tKtnG43QONVFf4WVheAjCX_CoDqo9k2Xf-6hW-5JlF6btXfmjlupvsaq40pkF2ubeW1RXIbayVwlvwbD39uiivh8LhgvDVFWdf3DdAMKj3O73cTaU-0vd6-PVxxJpimsCEjcrFZdMnmUDtTJBDA9egnDaZR8DAuxM',
                        'q' => '5AqNzF8Ou1Vrlm__dg4htzffAKX52aB0945VUJzs78FeP1EwxuiG8xf55iUCqkNnwq7z8R9aXdu3v-RsBN4GtPuZCLxhfvb9sW6Pt207-FHSRrioj5rlviXxgR7TSlCm5Lmyu_1Sw7HIsyw0Jq-ak0FU-tWvM9X5PG-7o1MSX8c',
                        'dp' => 'Nf8XcKoOOMQWdKvhoGRDVbawGAi1bm3_0x74TPvjllj0G9aqJnVo6ZSZ3Tpnxsu1ID0gxlKoAoTUQ20yl_rupMuFeunyBhjo3FluRcEdBERTrcyvhi5ZDYczSe9sZPGIZ0WTCTmCzEk7dCHA0CKeCw5D_820GTt04hLXsOulo7U',
                        'dq' => 'MrNyAW1lDhuY1xLBnpLXxi-i4jcEzPES8HNx3oF1YH0Cols_2Amc73F2O0ghRo_EAxH45LRO2C1gtkZoCdD_dr-1r66KkrsBfrCRPXwI6FXwxY6K05rh15wCDO44lf5GjPYImilhfGcLs2JxmeRTHshYx4g48vJw_pHtCwwOOsM',
                        'qi' => 'Ey9cXGlGbA2j5bO3l_JyPs43myTyqKfm6F6TMVeJi0lF0ypUS6KAMLZYHzaQg112FatsYS-OTWgcZBHbN745cI_Aq5-d63jSUlm9LxMycKFI0CAjn-8Q_H7Y_DbhLzH-0dQTticfzKFgCKKZmIVHzoHv6dSOwMSaYaWaMlh7uwo'
                    ]
                ]
            ]),
            new JWKSet([
                'keys' => [
                    [
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'x' => 'h72PwAzJdnNUnTfvubnn0T0HFV9Wyofo23nfERxw9gM',
                        'y' => 'Z1lmCtUhoFuPAqGxkxSCQNe4UKdlD1GU0TzDgG4sJfk',
                    ]
                ]
            ])
        );

        $cut->extractToken('eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJ0eXB1WWdlX0phWVVDeVl4ZmxYV1doTDZnZWRqdEZtQm10S1pFdm94U1hJIn0.DaNr5BBVaZv-q9alooIbXsp4vCp-rPZixqpTaPgSrStP7UI96127ujKkpFi2IdJ4gRAyUvVxikB5KmSiCrheKkqyejsljJmDcaFuyGwYIu4NPWkkj44-fJVi0SVGenkXRunRr_vLRx-rFWRi_PKi5UznnWbEZHbfs9PFagMz8A4gi_izco0-qS4UhUsgSHoQXP_aPIEeLnW6erJtB4PHclUKZYuwNRXf8GpNb4SJuRMuv2kGLLlvwu2MAZcsHCaGNczewAq0PA-23VFhpt9qrMgFq3-rrL4GJA1JmNLQSBDhqdQFm-OzcLZm0nYdPT_j2WO5BWo-Eu1dofhAxmtJvw.6_x9l0IPPglw37Z-n-0Q6Q.ys2d7WFcaY6uA1zcKiYhyA._ma6il-3lkCkE0rsAdciNA');
    }
}

/*
Keys used:

encryption key:
{ kty: 'RSA',
  kid: 'typuYge_JaYUCyYxflXWWhL6gedjtFmBmtKZEvoxSXI',
  n: '4cagIQBAMGVRQczExA3eX9TBdAG78tKU5TFWUn7XzHmhnXEJpuNvg_14v8u8RRW6MG9FlBobVgvn2WvDO3WvZuNw3xOuPWJTjRFozqAOyn2CxQvmMJ8FFpBN7xFc6EMVCMEH-BZG5kZaIl0FxMYJRL64nIyIoyBQ_oYBU-MHN17F2sahfL66LPw7nH0KZxLFGWZcG3NKeJ74mFe9oI1z5SAzNtklE5tURYVI_GHjzrB5-5BBDzQMNOh8GJhKtBcTQu6HiMqMa2GbDS22bdx5CD9-f6xJGEohxFwAmvD188nNlnnUHC6nqn1oGI3uqbAuDe9ManncbbvQd8-bq5N4xQ',
  e: 'AQAB',
  d: 's205xuA_Ivbx-7vzR-fJqRkY4MucBV8LS5XJB2icsXicUtYJmKK49glTlAEizzh0LpfPkOKqhNiTWfvFPRTK35azFeW7HDdvNPX39_XFq3DRoy1Qs6U80vC9rtd6oW7mYX2eiq-RiuGwMg0BT58esI5tgqRA1nsRQyVWGsea7YmaRVbeYL06ytWc4rsBBBBr3AFV6bHqX6uwyh7ZhKwCd9xZiO0AWzrdPFo3GQDfOvR8Q4sYk2k7Bs6bmVA58sTo8srxU1PB77Eb8Bg79AVyc3GnKXp43HEfNttqiluxj8G3632pEOeeo9PI1WvqEQwnGEzZZv8xlCuqmcTKYN9VBQ',
  p: '_XT4VM-Jh_tKtnG43QONVFf4WVheAjCX_CoDqo9k2Xf-6hW-5JlF6btXfmjlupvsaq40pkF2ubeW1RXIbayVwlvwbD39uiivh8LhgvDVFWdf3DdAMKj3O73cTaU-0vd6-PVxxJpimsCEjcrFZdMnmUDtTJBDA9egnDaZR8DAuxM',
  q: '5AqNzF8Ou1Vrlm__dg4htzffAKX52aB0945VUJzs78FeP1EwxuiG8xf55iUCqkNnwq7z8R9aXdu3v-RsBN4GtPuZCLxhfvb9sW6Pt207-FHSRrioj5rlviXxgR7TSlCm5Lmyu_1Sw7HIsyw0Jq-ak0FU-tWvM9X5PG-7o1MSX8c',
  dp: 'Nf8XcKoOOMQWdKvhoGRDVbawGAi1bm3_0x74TPvjllj0G9aqJnVo6ZSZ3Tpnxsu1ID0gxlKoAoTUQ20yl_rupMuFeunyBhjo3FluRcEdBERTrcyvhi5ZDYczSe9sZPGIZ0WTCTmCzEk7dCHA0CKeCw5D_820GTt04hLXsOulo7U',
  dq: 'MrNyAW1lDhuY1xLBnpLXxi-i4jcEzPES8HNx3oF1YH0Cols_2Amc73F2O0ghRo_EAxH45LRO2C1gtkZoCdD_dr-1r66KkrsBfrCRPXwI6FXwxY6K05rh15wCDO44lf5GjPYImilhfGcLs2JxmeRTHshYx4g48vJw_pHtCwwOOsM',
  qi: 'Ey9cXGlGbA2j5bO3l_JyPs43myTyqKfm6F6TMVeJi0lF0ypUS6KAMLZYHzaQg112FatsYS-OTWgcZBHbN745cI_Aq5-d63jSUlm9LxMycKFI0CAjn-8Q_H7Y_DbhLzH-0dQTticfzKFgCKKZmIVHzoHv6dSOwMSaYaWaMlh7uwo' }

signing key:
{ kty: 'EC',
  kid: 'XrV2NRHPrhqZhVVL8Mu44wkO4kxl3Y9X_Ts7iqqj0j4',
  crv: 'P-256',
  x: 'a1cGHQErfR67SigVr-nYFofx2BD5Jf7-BcTyWuuU_PM',
  y: '4A9M4FCL-ILPmkveCYhOn5NfqqvITgha9_XjEj30q3s',
  d: 'eRR20pryjBybzTo0_jyFFY_ma3PaloqZ0uhGc13r1Qk' }
*/