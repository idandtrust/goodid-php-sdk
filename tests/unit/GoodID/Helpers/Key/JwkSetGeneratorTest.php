<?php

namespace GoodID\Helpers\Key;

use GoodID\Helpers\Http\HttpResponse;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\Key\RSAPublicKey;

class JwkSetGeneratorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCanGenerateJwksUriContentWithoutExistingJwksUri()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator();

        $this->assertJsonStringEqualsJsonString(
            $this->jwksUriContent,
            $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey));
    }

    /**
     * @test
     */
    public function itCanGenerateJwksUriContentWithExistingJwksUri()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(200, $this->oldJwksUriContent));

        $this->assertJsonStringEqualsJsonString(
            $this->combinedJwksUriContent,
            $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey, 'old-jwks-uri'));
    }

    /**
     * @test
     */
    public function itCanGenerateJwksUriWithSigKeyEqualsEncKey()
    {
        $key = new RSAPublicKey($this->sigPubKey);

        $jwkSetGenerator = $this->createJwkSetGenerator();

        $this->assertJsonStringEqualsJsonString(
            $this->jwksUriContentSigEqualsEnc,
            $jwkSetGenerator->generateJwksUriContent($key, $key));
    }

    /**
     * @test
     */
    public function itCanGenerateJwksUriWithSigKeyEqualsEncKeyWithExistingJwksUri()
    {
        $key = new RSAPublicKey($this->sigPubKey);
        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(200, $this->oldJwksUriContentSigEqualsEnc));

        $this->assertJsonStringEqualsJsonString(
            $this->combinedJwksUriContentSigEqualsEnc,
            $jwkSetGenerator->generateJwksUriContent($key, $key, 'old-jwks-uri'));
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Format of existing JWKS URI content is invalid
     */
    public function itFailsIfExistingJwksUriIsNotJson()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(200, $this->oldJwksUriContentNotJson));

        $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey, 'old-jwks-uri');
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Format of existing JWKS URI content is invalid
     */
    public function itFailsIfExistingJwksUriIsNotObject()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(200, $this->oldJwksUriContentNotObject));

        $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey, 'old-jwks-uri');
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Format of existing JWKS URI content is invalid
     */
    public function itFailsIfExistingJwksUriDoesNotHaveKeys()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(200, $this->oldJwksUriContentWithoutKeys));

        $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey, 'old-jwks-uri');
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Format of existing JWKS URI content is invalid
     */
    public function itFailsIfExistingJwksUriHasKeysButItIsNotAnArray()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(200, $this->oldJwksUriContentWithKeysNotArray));

        $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey, 'old-jwks-uri');
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Existing JWKS URI returned 401, not allowed
     */
    public function itFailsWhenHttpStatusCodeIsNotOk()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(401, 'not allowed'));

        $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey, 'old-jwks-uri');
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Result would contain a duplicate use-kid pair
     *
     */
    public function itFailsIfUseKidPairWouldBeDuplicate()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(200, $this->jwksUriContent));
        $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey, 'old-jwks-uri');
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Duplicate use-kid pair in existing JWKS URI content
     *
     */
    public function itFailsIfUseKidPairIsDuplicateOnJwksUri()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey);
        $encPrivKey = new RSAPrivateKey($this->encPrivKey);

        $jwkSetGenerator = $this->createJwkSetGenerator(new HttpResponse(200, $this->oldJwksUriContentDuplicated));
        $jwkSetGenerator->generateJwksUriContent($sigPubKey, $encPrivKey, 'old-jwks-uri');
    }

    /**
     * Partial mock
     *
     * @param HttpResponse $response
     * @return JwkSetGenerator
     */
    private function createJwkSetGenerator(HttpResponse $response = null)
    {
        $jwkSetGenerator = $this->getMockBuilder(JwkSetGenerator::class)
            ->setMethods(['callEndpoint'])
            ->getMock();
        $jwkSetGenerator->method('callEndpoint')
            ->willReturn($response);

        return $jwkSetGenerator;
    }

    private $sigPubKey =
'-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5pUbc0tbzU6GCB0/ja+
UTCx9AFqNsKjS/nqKzzHbpXF//XbONjkYV7xQfV4D/a+FbAvQqJidR8P3ndb2zfZ
3xuZDd6hzHBMf3GtQldDS2y1/JPhdKLG5/rbjOke9b8mR/zqq8fo+GK0njffAEIQ
y4P5J50ANFx+8X6UulNUQ/AU/qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9+m
PfSDrvvGK9/O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt++
MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3
WQIDAQAB
-----END PUBLIC KEY-----';

    private $encPrivKey =
'-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1OfO1Si54G0DvrNMJrH8+VeP9Oti1bmm/gPcGN0HKCbRxwtW
Wfmh2ktwyBZx1UdCFU8NEbBs1UACR5ipNtfoTmekpe4rFajvHDSiW1Fcun2oizoW
QuRN/og25r/DL1s0C5aiLkFK5wt4mwGYC5DV5rYbEDX6/RzftaLNG1ZAQQv/gcNo
5quGXT79C/qK9M8YLFtQ6Ql1FWhJ6r/leNdmTZxWkyhW+eswTd2XlclzBH2YEm+G
LQ6FbXLj47+zvruclg8odzQWfQx7/+fxksqAc7PVkR1pIw83GoV1MQuZgDSvFce0
j/2dM5cc5yuaNQ9iCWDtDSAuWOFefaKTf768ywIDAQABAoIBAQCtkwdHNVrFI1to
P9kXuwhZaA/PR5BeWmtQsGjiRGCvVWa1dgLCfAh+Zf7ewZ2wmdXAdaBcCY/RE8xH
/qgGNGQKd+j99nxdvkqini63cE+/Iu8kAwlfI66KkxbfbPt+QkbeI8K5HzYnw2xi
QxxoYX5iB5lsz/V+IeootT+ux9S+scEwfwzqQmehX9PKDCp/MA6JytHgPjgBF7Vd
4NBhUHGtSwZDjmMQB5LR83RIeaRx61U+k+arDa3FqzkvYZ6vQeZBX+AWZLhzZuaZ
6acWIxrpavcrB81q25gAC26kpdhLnyQXkUyDGlQnx2asy3BUT3Mg0tWOCMg2olOa
wB5gk3cRAoGBAP+wR164bXtE6n3c9NhA5EVwmhS2VPjv1n3oExW/UCovxTYJnW7U
YmlL7BFZaE1lEsrMVBZ/vYx3EkRaNYemWnIXDoJia17/+l1PHFyE4zvcTicocQBg
sZTf7YFI5UTQK3+m+X8981xFZEkfrA6Gj1172LKCJpWBqR/gIMYsMPS/AoGBANUq
MJbFTmRPdievbgMQ20gN5nSnYfe8vKXzQXcuOy6sY2FwCkRAvIAWvIgCTKyOz8JF
/wvoXOE4Q0li8lXLbaAxhr24YmsJqSHvaqFF7p9TqvEVuLiDJ2RTqhlWEduYL/om
Zu0h8NgTqL+7QrqW/rPu0LDTo3KvelqhNQ8Wsf71AoGATK7KiM7ZDto5VWwaBm1X
yLefjkysqUgM1Q/wAVqyKSTQiYdSrvWFWj0J3J4q2ONSQn4LTgAbke/4C4XefgNX
JtZhZJstxn0Q0kEyqVC1cbN9wOKxGULmn1aVPWvmTr/7+7nRI+cpgGfTTtbv3B9h
CdFlyQudlMMhPM0UJzsDp7MCgYAAiI5+khfUIG7HQqUf1Nb3ozFEcXbJS+uc7rLn
PXJgd4X4JHOiIBdYqrXmETtn4yOZ9NriiL5SwfVJJbo9hLjNgdI4f1GfuvJ1Z0f5
B1fFhkwTNl6z94ANvDfcwF5jEkpscdQoG8GiiMoPUMSl+uLASIS1LJJoIxBHUcf0
NbZUUQKBgGro6eUPiee4v5iB47ceCdrAwN8LQKd/xuTg68TKRO6RO1A/DuJbkluD
BJaKtsprQIrIAbnkxPLNx9iCwNteww8aOh0HJWEV/0t95rXWuKDmXriXO4++wyIA
XGMjP3IOvNn84lBTD+aJxUpNQmTbKDLqpPiWXncoa7CxnXsPjom/
-----END RSA PRIVATE KEY-----';

    private $jwksUriContent = '{"keys":[{"kty":"RSA","n":"v5pUbc0tbzU6GCB0_ja-UTCx9AFqNsKjS_nqKzzHbpXF__XbONjkYV7xQfV4D_a-FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1_JPhdKLG5_rbjOke9b8mR_zqq8fo-GK0njffAEIQy4P5J50ANFx-8X6UulNUQ_AU_qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9-mPfSDrvvGK9_O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt--MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQ","e":"AQAB","use":"sig","kid":"Fpa_c"},{"kty":"RSA","n":"1OfO1Si54G0DvrNMJrH8-VeP9Oti1bmm_gPcGN0HKCbRxwtWWfmh2ktwyBZx1UdCFU8NEbBs1UACR5ipNtfoTmekpe4rFajvHDSiW1Fcun2oizoWQuRN_og25r_DL1s0C5aiLkFK5wt4mwGYC5DV5rYbEDX6_RzftaLNG1ZAQQv_gcNo5quGXT79C_qK9M8YLFtQ6Ql1FWhJ6r_leNdmTZxWkyhW-eswTd2XlclzBH2YEm-GLQ6FbXLj47-zvruclg8odzQWfQx7_-fxksqAc7PVkR1pIw83GoV1MQuZgDSvFce0j_2dM5cc5yuaNQ9iCWDtDSAuWOFefaKTf768yw","e":"AQAB","use":"enc","kid":"z03bX"}]}';
    private $jwksUriContentSigEqualsEnc = '{"keys":[{"kty":"RSA","n":"v5pUbc0tbzU6GCB0_ja-UTCx9AFqNsKjS_nqKzzHbpXF__XbONjkYV7xQfV4D_a-FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1_JPhdKLG5_rbjOke9b8mR_zqq8fo-GK0njffAEIQy4P5J50ANFx-8X6UulNUQ_AU_qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9-mPfSDrvvGK9_O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt--MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQ","e":"AQAB","use":"sig","kid":"Fpa_c"},{"kty":"RSA","n":"v5pUbc0tbzU6GCB0_ja-UTCx9AFqNsKjS_nqKzzHbpXF__XbONjkYV7xQfV4D_a-FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1_JPhdKLG5_rbjOke9b8mR_zqq8fo-GK0njffAEIQy4P5J50ANFx-8X6UulNUQ_AU_qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9-mPfSDrvvGK9_O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt--MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQ","e":"AQAB","use":"enc","kid":"Fpa_c"}]}';
    private $oldJwksUriContent = '{"keys":[{"kty":"RSA","n":"zlqZ7gAruz0gt6tgARAI7Rkv6NK0DiG3tLvY3iOFVoOZ3XwNe-scgpi-kvtxjs6xflGRsLZnmmhr1KN_3Y1lg3VVITYYouqYFfJM6B5FCqiiu_yIaU2TOfOXVYwprQzNT-GTm-8F2QVkFbz66uuyIfKSsr9YUBjuWH-cTkyw8kmT5MXMPaskdCFS-pgU_M7XemyFBGUusAPT_oWoV3olokAz9QG6NQYmM4bSECdQWCMbD_gntwS5_jnsb308F5L8ioTNMx8aUe0a9HW0oFpqK73O4bupm6G5N2xWGrtMzUTeuvPn9sIqRpS_XiAzRdjkCQ81jZoMa1GggBBxBnG-fw","e":"AQAB","use":"sig","kid":"bUbMB"},{"kty":"RSA","n":"qQOWL_mlcIQOnfAW6Rt7A2nlX4-RLlcgNcGy9B_AZy-kXW44N6WMpydCi4n12fdE-666k_w1kMjF00AgPZe-OZ6xbvtul_9_N5HcGN25T3OI_-7ogp6cjv4siF9dNjXQEnlhrTPeJhUbHNhKuSa7McJOxpRxURkhFE34cZkg6xYk9pVa_GuaMpUflhGH7xbNz76I4yeivy5tuRe5yB-go11tg0nsTglUEZEFklBOgiRZVUra5NTJslc0x3N1Xmwk5ySiumZ3qmas-W7VP3Td118ZaDY8diyxI_LEY-Ynw531rLgM0kxh4FuMlrr-BaL3yjeZ0PmZCeRw-3qoy6XkwQ","e":"AQAB","use":"enc","kid":"3nhRr"}]}';
    private $oldJwksUriContentDuplicated = '{"keys":[{"kty":"RSA","n":"zlqZ7gAruz0gt6tgARAI7Rkv6NK0DiG3tLvY3iOFVoOZ3XwNe-scgpi-kvtxjs6xflGRsLZnmmhr1KN_3Y1lg3VVITYYouqYFfJM6B5FCqiiu_yIaU2TOfOXVYwprQzNT-GTm-8F2QVkFbz66uuyIfKSsr9YUBjuWH-cTkyw8kmT5MXMPaskdCFS-pgU_M7XemyFBGUusAPT_oWoV3olokAz9QG6NQYmM4bSECdQWCMbD_gntwS5_jnsb308F5L8ioTNMx8aUe0a9HW0oFpqK73O4bupm6G5N2xWGrtMzUTeuvPn9sIqRpS_XiAzRdjkCQ81jZoMa1GggBBxBnG-fw","e":"AQAB","use":"sig","kid":"bUbMB"},{"kty":"RSA","n":"zlqZ7gAruz0gt6tgARAI7Rkv6NK0DiG3tLvY3iOFVoOZ3XwNe-scgpi-kvtxjs6xflGRsLZnmmhr1KN_3Y1lg3VVITYYouqYFfJM6B5FCqiiu_yIaU2TOfOXVYwprQzNT-GTm-8F2QVkFbz66uuyIfKSsr9YUBjuWH-cTkyw8kmT5MXMPaskdCFS-pgU_M7XemyFBGUusAPT_oWoV3olokAz9QG6NQYmM4bSECdQWCMbD_gntwS5_jnsb308F5L8ioTNMx8aUe0a9HW0oFpqK73O4bupm6G5N2xWGrtMzUTeuvPn9sIqRpS_XiAzRdjkCQ81jZoMa1GggBBxBnG-fw","e":"AQAB","use":"sig","kid":"bUbMB"}]}';
    private $oldJwksUriContentSigEqualsEnc = '{"keys":[{"kty":"RSA","n":"zlqZ7gAruz0gt6tgARAI7Rkv6NK0DiG3tLvY3iOFVoOZ3XwNe-scgpi-kvtxjs6xflGRsLZnmmhr1KN_3Y1lg3VVITYYouqYFfJM6B5FCqiiu_yIaU2TOfOXVYwprQzNT-GTm-8F2QVkFbz66uuyIfKSsr9YUBjuWH-cTkyw8kmT5MXMPaskdCFS-pgU_M7XemyFBGUusAPT_oWoV3olokAz9QG6NQYmM4bSECdQWCMbD_gntwS5_jnsb308F5L8ioTNMx8aUe0a9HW0oFpqK73O4bupm6G5N2xWGrtMzUTeuvPn9sIqRpS_XiAzRdjkCQ81jZoMa1GggBBxBnG-fw","e":"AQAB","use":"sig","kid":"bUbMB"},{"kty":"RSA","n":"zlqZ7gAruz0gt6tgARAI7Rkv6NK0DiG3tLvY3iOFVoOZ3XwNe-scgpi-kvtxjs6xflGRsLZnmmhr1KN_3Y1lg3VVITYYouqYFfJM6B5FCqiiu_yIaU2TOfOXVYwprQzNT-GTm-8F2QVkFbz66uuyIfKSsr9YUBjuWH-cTkyw8kmT5MXMPaskdCFS-pgU_M7XemyFBGUusAPT_oWoV3olokAz9QG6NQYmM4bSECdQWCMbD_gntwS5_jnsb308F5L8ioTNMx8aUe0a9HW0oFpqK73O4bupm6G5N2xWGrtMzUTeuvPn9sIqRpS_XiAzRdjkCQ81jZoMa1GggBBxBnG-fw","e":"AQAB","use":"enc","kid":"bUbMB"}]}';
    private $combinedJwksUriContent = '{"keys":[{"kty":"RSA","n":"zlqZ7gAruz0gt6tgARAI7Rkv6NK0DiG3tLvY3iOFVoOZ3XwNe-scgpi-kvtxjs6xflGRsLZnmmhr1KN_3Y1lg3VVITYYouqYFfJM6B5FCqiiu_yIaU2TOfOXVYwprQzNT-GTm-8F2QVkFbz66uuyIfKSsr9YUBjuWH-cTkyw8kmT5MXMPaskdCFS-pgU_M7XemyFBGUusAPT_oWoV3olokAz9QG6NQYmM4bSECdQWCMbD_gntwS5_jnsb308F5L8ioTNMx8aUe0a9HW0oFpqK73O4bupm6G5N2xWGrtMzUTeuvPn9sIqRpS_XiAzRdjkCQ81jZoMa1GggBBxBnG-fw","e":"AQAB","use":"sig","kid":"bUbMB"},{"kty":"RSA","n":"qQOWL_mlcIQOnfAW6Rt7A2nlX4-RLlcgNcGy9B_AZy-kXW44N6WMpydCi4n12fdE-666k_w1kMjF00AgPZe-OZ6xbvtul_9_N5HcGN25T3OI_-7ogp6cjv4siF9dNjXQEnlhrTPeJhUbHNhKuSa7McJOxpRxURkhFE34cZkg6xYk9pVa_GuaMpUflhGH7xbNz76I4yeivy5tuRe5yB-go11tg0nsTglUEZEFklBOgiRZVUra5NTJslc0x3N1Xmwk5ySiumZ3qmas-W7VP3Td118ZaDY8diyxI_LEY-Ynw531rLgM0kxh4FuMlrr-BaL3yjeZ0PmZCeRw-3qoy6XkwQ","e":"AQAB","use":"enc","kid":"3nhRr"},{"kty":"RSA","n":"v5pUbc0tbzU6GCB0_ja-UTCx9AFqNsKjS_nqKzzHbpXF__XbONjkYV7xQfV4D_a-FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1_JPhdKLG5_rbjOke9b8mR_zqq8fo-GK0njffAEIQy4P5J50ANFx-8X6UulNUQ_AU_qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9-mPfSDrvvGK9_O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt--MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQ","e":"AQAB","use":"sig","kid":"Fpa_c"},{"kty":"RSA","n":"1OfO1Si54G0DvrNMJrH8-VeP9Oti1bmm_gPcGN0HKCbRxwtWWfmh2ktwyBZx1UdCFU8NEbBs1UACR5ipNtfoTmekpe4rFajvHDSiW1Fcun2oizoWQuRN_og25r_DL1s0C5aiLkFK5wt4mwGYC5DV5rYbEDX6_RzftaLNG1ZAQQv_gcNo5quGXT79C_qK9M8YLFtQ6Ql1FWhJ6r_leNdmTZxWkyhW-eswTd2XlclzBH2YEm-GLQ6FbXLj47-zvruclg8odzQWfQx7_-fxksqAc7PVkR1pIw83GoV1MQuZgDSvFce0j_2dM5cc5yuaNQ9iCWDtDSAuWOFefaKTf768yw","e":"AQAB","use":"enc","kid":"z03bX"}]}';
    private $combinedJwksUriContentSigEqualsEnc = '{"keys":[{"kty":"RSA","n":"zlqZ7gAruz0gt6tgARAI7Rkv6NK0DiG3tLvY3iOFVoOZ3XwNe-scgpi-kvtxjs6xflGRsLZnmmhr1KN_3Y1lg3VVITYYouqYFfJM6B5FCqiiu_yIaU2TOfOXVYwprQzNT-GTm-8F2QVkFbz66uuyIfKSsr9YUBjuWH-cTkyw8kmT5MXMPaskdCFS-pgU_M7XemyFBGUusAPT_oWoV3olokAz9QG6NQYmM4bSECdQWCMbD_gntwS5_jnsb308F5L8ioTNMx8aUe0a9HW0oFpqK73O4bupm6G5N2xWGrtMzUTeuvPn9sIqRpS_XiAzRdjkCQ81jZoMa1GggBBxBnG-fw","e":"AQAB","use":"sig","kid":"bUbMB"},{"kty":"RSA","n":"zlqZ7gAruz0gt6tgARAI7Rkv6NK0DiG3tLvY3iOFVoOZ3XwNe-scgpi-kvtxjs6xflGRsLZnmmhr1KN_3Y1lg3VVITYYouqYFfJM6B5FCqiiu_yIaU2TOfOXVYwprQzNT-GTm-8F2QVkFbz66uuyIfKSsr9YUBjuWH-cTkyw8kmT5MXMPaskdCFS-pgU_M7XemyFBGUusAPT_oWoV3olokAz9QG6NQYmM4bSECdQWCMbD_gntwS5_jnsb308F5L8ioTNMx8aUe0a9HW0oFpqK73O4bupm6G5N2xWGrtMzUTeuvPn9sIqRpS_XiAzRdjkCQ81jZoMa1GggBBxBnG-fw","e":"AQAB","use":"enc","kid":"bUbMB"},{"kty":"RSA","n":"v5pUbc0tbzU6GCB0_ja-UTCx9AFqNsKjS_nqKzzHbpXF__XbONjkYV7xQfV4D_a-FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1_JPhdKLG5_rbjOke9b8mR_zqq8fo-GK0njffAEIQy4P5J50ANFx-8X6UulNUQ_AU_qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9-mPfSDrvvGK9_O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt--MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQ","e":"AQAB","use":"sig","kid":"Fpa_c"},{"kty":"RSA","n":"v5pUbc0tbzU6GCB0_ja-UTCx9AFqNsKjS_nqKzzHbpXF__XbONjkYV7xQfV4D_a-FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1_JPhdKLG5_rbjOke9b8mR_zqq8fo-GK0njffAEIQy4P5J50ANFx-8X6UulNUQ_AU_qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9-mPfSDrvvGK9_O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt--MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQ","e":"AQAB","use":"enc","kid":"Fpa_c"}]}';
    private $oldJwksUriContentNotJson = '{';
    private $oldJwksUriContentNotObject = '"asd"';
    private $oldJwksUriContentWithoutKeys = '{}';
    private $oldJwksUriContentWithKeysNotArray = '{"keys":"asd"}';
}
