<?php
/**
 * Copyright 2017 ID&Trust, Ltd.
 *
 * You are hereby granted a non-exclusive, worldwide, royalty-free license to
 * use, copy, modify, and distribute this software in source code or binary form
 * for use in connection with the web services and APIs provided by ID&Trust.
 *
 * As with any software that integrates with the GoodID platform, your use
 * of this software is subject to the GoodID Terms of Service
 * (https://goodid.net/docs/tos).
 * This copyright notice shall be included in all copies or substantial portions
 * of the software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

namespace GoodID\Helpers\Response;

// @TODO
class LegacyClaimAdapter
{
    /**
     * ID token standard claims
     */
    private static $idTokenStandardClaims = [
        'iss',
        'sub',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'acr',
        'amr',
        'azp',
        'at_hash',
        'c_hash',
        'seal',
        'email_hash',
        'user',
        'uih',
    ];

    /**
     * UserInfo standard claims
     */
    private static $userInfoStandardClaims = [
        'iss',
        'sub',
        'aud',
    ];

    /**
     * @param array $userInfo
     *
     * @return array
     */
    public function adaptUserInfo(array $userInfo)
    {
        if (array_key_exists('claims', $userInfo)) {
            return $userInfo;
        }

        $claims = [];
        foreach (array_keys($userInfo) as $claimName) {
            if (!in_array($claimName, self::$userInfoStandardClaims)) {
                $claims[$claimName] = $userInfo[$claimName];
                unset($userInfo[$claimName]);
            }
        }
        $userInfo['claims'] = $claims;

        return $userInfo;
    }

    /**
     * @param array $idToken
     *
     * @return array
     */
    public function adaptIdToken(array $idToken)
    {
        foreach (array_keys($idToken) as $claimName) {
            if (!in_array($claimName, self::$idTokenStandardClaims)) {
                unset($idToken[$claimName]);
            }
        }

        return $idToken;
    }
}