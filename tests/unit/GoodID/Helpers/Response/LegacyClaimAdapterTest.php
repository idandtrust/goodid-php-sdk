<?php

namespace GoodID\Helpers\Response;

class LegacyClaimAdapterTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itStripsNonStandardClaimsInIdToken()
    {
        $idTokenClaimsToAdapt = [
            'iss' => 'https://idp.goodid.net',
            'sub' => 'W3NfxL85SCIKtNHh49MSJTX7J1g9YNtYSeVu93pDKAo',
            'aud' => '4b1d5c57f6fa07e18c482a1f98a24777',
            'exp' => 1532620973,
            'iat' => 1532620673,
            'auth_time' => 1532620973,
            'nonce' => 'f5d35d21',
            'acr' => '2',
            'amr' => ['amr1', 'amr2'],
            'azp' => '4b1d5c57f6fa07e18c482a1f98a24777',
            'at_hash' => 'ed7ba196bd5be2dd73622a',
            'c_hash' => 'zHyTeH84fwzROuYiIWYO-w',
            'email_hash' => 'Some email hash',
            'uih' => 'userinfo hash',
            'some_claim' => 'Something',
            'some_other_claim' => ['Something else'],
        ];

        $adaptedClaims = (new LegacyClaimAdapter())->adaptIdToken($idTokenClaimsToAdapt);
        $this->assertEquals([
            'iss' => 'https://idp.goodid.net',
            'sub' => 'W3NfxL85SCIKtNHh49MSJTX7J1g9YNtYSeVu93pDKAo',
            'aud' => '4b1d5c57f6fa07e18c482a1f98a24777',
            'exp' => 1532620973,
            'iat' => 1532620673,
            'auth_time' => 1532620973,
            'nonce' => 'f5d35d21',
            'acr' => '2',
            'amr' => ['amr1', 'amr2'],
            'azp' => '4b1d5c57f6fa07e18c482a1f98a24777',
            'at_hash' => 'ed7ba196bd5be2dd73622a',
            'c_hash' => 'zHyTeH84fwzROuYiIWYO-w',
            'email_hash' => 'Some email hash',
            'uih' => 'userinfo hash',
        ], $adaptedClaims);
    }

    /**
     * @test
     */
    public function itAdaptsNonStandardClaimsInUserInfo()
    {
        $userInfoClaimsToAdapt = [
            'iss' => 'https://idp.goodid.net',
            'sub' => 'W3NfxL85SCIKtNHh49MSJTX7J1g9YNtYSeVu93pDKAo',
            'aud' => '4b1d5c57f6fa07e18c482a1f98a24777',
            'some_claim' => 'Something',
            'some_other_claim' => ['Something else'],
        ];

        $adaptedClaims = (new LegacyClaimAdapter())->adaptUserInfo($userInfoClaimsToAdapt);
        $this->assertEquals([
            'iss' => 'https://idp.goodid.net',
            'sub' => 'W3NfxL85SCIKtNHh49MSJTX7J1g9YNtYSeVu93pDKAo',
            'aud' => '4b1d5c57f6fa07e18c482a1f98a24777',
            'claims' => [
                'some_claim' => 'Something',
                'some_other_claim' => ['Something else'],
            ],
        ], $adaptedClaims);
    }

    /**
     * @test
     */
    public function itDoesNothingIfClaimsClaimExists()
    {
        $userInfoClaimsToAdapt = [
            'iss' => 'https://idp.goodid.net',
            'sub' => 'W3NfxL85SCIKtNHh49MSJTX7J1g9YNtYSeVu93pDKAo',
            'aud' => '4b1d5c57f6fa07e18c482a1f98a24777',
            'claims' => [
                'some_claim' => 'Something',
                'some_other_claim' => ['Something else'],
            ],
        ];

        $adaptedClaims = (new LegacyClaimAdapter())->adaptUserInfo($userInfoClaimsToAdapt);
        $this->assertEquals([
            'iss' => 'https://idp.goodid.net',
            'sub' => 'W3NfxL85SCIKtNHh49MSJTX7J1g9YNtYSeVu93pDKAo',
            'aud' => '4b1d5c57f6fa07e18c482a1f98a24777',
            'claims' => [
                'some_claim' => 'Something',
                'some_other_claim' => ['Something else'],
            ],
        ], $adaptedClaims);
    }
}
