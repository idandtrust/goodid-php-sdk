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

namespace GoodIDPass\PassApi;

interface GoodidPassApiInterface
{
    /**
     * @return array
     *
     * @throws PassApiException
     */
    public function getPasses();

    /**
     * @param string $templateId
     * @param string $passUrl
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function issuePass($templateId, $passUrl);

    /**
     * @param string $serial
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function getPass($serial);

    /**
     * @param string $serial
     * @param string|null $passUrl
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function updatePass($serial, $passUrl = null);

    /**
     * @param string $serial
     *
     * @return void
     */
    public function deletePass($serial);

    /**
     * @param string $serial
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function getPassDownloadLink($serial);

    /**
     * @param string $serial
     * @param string $sub
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function associatePassWithSub($serial, $sub);

    /**
     * @param string $serial
     * @param string $sub
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function dissociatePassFromSub($serial, $sub);

    /**
     * @param string $templateId
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function getPassTemplate($templateId);

    /**
     * @param string $templateId
     * @param array $templateData
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function upsertPassTemplate($templateId, $templateData);

    /**
     * @param string $templateId
     *
     * @return void
     *
     * @throws PassApiException
     */
    public function deletePassTemplate($templateId);
}
