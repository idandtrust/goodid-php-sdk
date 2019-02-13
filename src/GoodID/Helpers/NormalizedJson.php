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

use Base64Url\Base64Url;

final class NormalizedJson {
    /**
     * @param array $arr
     *
     * @return array
     */
    private static function sortArray(array $arr) {
        $r = [];

        $keys = array_keys($arr);
        sort($keys);
        foreach ($keys as $k) {
            if (is_object($arr[$k])) {
                $r[$k] = self::sortObject($arr[$k]);
            } elseif (is_array($arr[$k])) {
                $r[$k] = self::sortArray($arr[$k]);
            } else {
                $r[$k] = $arr[$k];
            }
        }
        return $r;
    }

    /**
     * @param \stdClass $obj
     *
     * @return object
     */
    private static function sortObject(\stdClass $obj) {
        $newObj = [];

        $keys = array_keys((array) $obj);
        sort($keys);
        foreach ($keys as $k) {
            $v = $obj->{$k};
            if (is_object($v)) {
                $newObj[$k] = self::sortObject($v);
            } elseif (is_array($v)) {
                $newObj[$k] = self::sortArray($v);
            } else {
                $newObj[$k] = $v;
            }
        }
        return (object) $newObj;
    }

    /**
     * @param \stdClass $obj
     *
     * @return string
     */
    public static function encode(\stdClass $obj) {
        return json_encode(self::sortObject($obj), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @param \stdClass $obj
     *
     * @return string
     */
    public static function hash(\stdClass $obj) {
        return Base64Url::encode(hash('sha256', self::encode($obj), true));
    }
}
