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

namespace GoodID\Helpers;

/**
 * JwtUtil class
 */
final class JwtUtil
{
    /**
     * Determines if a JWT string is a compact JWS
     * Its internal structure and validity is NOT checked
     *
     * @param string $jwt JWT string
     *
     * @return bool isCompactJWS
     */
    public static function isCompactJws($jwt)
    {
        return substr_count($jwt, '.') === 2;
    }

    /**
     * Determines if a JWT string is a compact JWE
     * Its internal structure and validity is NOT checked
     *
     * @param string $jwt JWT string
     *
     * @return bool isCompactJWE
     */
    public static function isCompactJwe($jwt)
    {
        return substr_count($jwt, '.') === 4;
    }
}
