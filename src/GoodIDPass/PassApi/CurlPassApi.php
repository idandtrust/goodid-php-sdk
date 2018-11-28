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

class CurlPassApi implements GoodidPassApiInterface
{
    /** @var string */
    private $clientId;
    /** @var string */
    private $clientSecret;
    /** @var string */
    private $passEndpoint;

    /**
     * @param string $clientId
     * @param string $clientSecret
     * @param string $passEndpoint
     */
    public function __construct($clientId, $clientSecret, $passEndpoint)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->passEndpoint = $passEndpoint;
    }

    /**
     * @return array
     *
     * @throws PassApiException
     */
    public function getPasses()
    {
        $response = $this->invokeCurl('/passes');
        return $response['data'];
    }

    /**
     * @param string $templateId
     * @param string $passUrl
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function issuePass($templateId, $passUrl)
    {
        $response = $this->invokeCurl('/passes', 'POST', http_build_query([
            'template_id' => $templateId,
            'pass_url' => $passUrl,
        ]));
        return $response['data'];
    }

    /**
     * @param string $serial
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function getPass($serial)
    {
        $response = $this->invokeCurl('/passes/' . $serial);
        return $response['data'];
    }

    /**
     * @param string $serial
     * @param string|null $passUrl
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function updatePass($serial, $passUrl = null)
    {
        $data = [];
        if ($passUrl !== null) {
            $data['pass_url'] = $passUrl;
        }

        $response = $this->invokeCurl('/passes/' . $serial, 'PATCH', http_build_query($data));
        return $response['data'];
    }

    /**
     * @param string $serial
     *
     * @return void
     */
    public function deletePass($serial)
    {
        $this->invokeCurl('/passes/' . $serial, 'DELETE');
    }

    /**
     * @param string $serial
     * @param string|null $data
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function getPassDownloadLink($serial, $data = null)
    {
        $url = '/passes/' . $serial . '/dl';
        $url .= $data ? '?data=' . $data : '';

        $response = $this->invokeCurl($url);
        return $response['data'];
    }

    /**
     * @param string $serial
     * @param string $language
     * @param string $recipient
     * @param array $data
     *
     * @throws PassApiException
     */
    public function sendEmailAboutPass($serial, $language, $recipient, array $data)
    {
        $this->invokeCurl('/passes/' . $serial . '/send', 'POST', http_build_query([
            'recipient' => $recipient,
            'language' => $language,
            'data' => $data,
        ]));
    }

    /**
     * @param string $serial
     * @param string $sub
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function associatePassWithSub($serial, $sub)
    {
        $response = $this->invokeCurl('/passes/' . $serial . '/associated-subs', 'POST', http_build_query([
            'sub' => $sub,
        ]));
        return $response['data'];
    }

    /**
     * @param string $serial
     * @param string $sub
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function dissociatePassFromSub($serial, $sub)
    {
        $response = $this->invokeCurl('/passes/' . $serial . '/associated-subs/' . $sub, 'DELETE');
        return $response['data'];
    }

    /**
     * @param string $templateId
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function getPassTemplate($templateId)
    {
        $response = $this->invokeCurl('/pass-templates/' . $templateId);
        return [
            'clientId' => $this->clientId,
            'templateId' => $templateId,
            'data' => $response['body']
        ];
    }

    /**
     * @param string $templateId
     * @param array $templateData
     *
     * @return array
     *
     * @throws PassApiException
     */
    public function upsertPassTemplate($templateId, $templateData)
    {
        $response = $this->invokeCurl('/pass-templates/' . $templateId, 'PUT', json_encode($templateData));
        return [
            'clientId' => $this->clientId,
            'templateId' => $templateId,
            'data' => $response['body']
        ];
    }

    /**
     * @param string $templateId
     *
     * @return void
     *
     * @throws PassApiException
     */
    public function deletePassTemplate($templateId)
    {
        $this->invokeCurl('/pass-templates/' . $templateId, 'DELETE');
    }

    /**
     * @param string $url
     * @param string $method
     * @param string $content
     *
     * @return array
     *
     * @throws PassApiException
     */
    private function invokeCurl($url, $method = 'GET', $content = '')
    {
        $ch = curl_init();
        try {
            $curlopts = [
                CURLOPT_URL => $this->passEndpoint . $url,
                CURLOPT_USERPWD => $this->clientId . ':' . $this->clientSecret,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => 1,
            ];
            if ($method !== 'GET') {
                $curlopts[CURLOPT_CUSTOMREQUEST] = $method;
                if (in_array($method, ['POST', 'PUT'], true)) {
                    $curlopts[CURLOPT_POSTFIELDS] = $content;
                }
            }
            curl_setopt_array($ch, $curlopts);

            $response = curl_exec($ch);
            if (curl_errno($ch) !== CURLE_OK) {
                throw new PassApiException('CURL error: ' . curl_error($ch));
            }

            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $headers = substr($response, 0, $headerSize);
            $body = substr($response, $headerSize);

            $data = null;
            $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if ($statusCode !== 204) {
                $data = json_decode($body, true);
                if ($data === null) {
                    throw new PassApiException('HTTP ' . $statusCode . '; could not parse response as json');
                }
            }
            if ($statusCode >= 400) {
                $message = 'Upstream error: ' . $data['error'];
                if (isset($response->reason)) {
                    $message .= '; caused by: ' . $response['reason'];
                }
                throw new PassApiException($message);
            }

            return [
                'data' => $data,
                'headers' => $headers,
            ];
        } finally {
            curl_close($ch);
        }
    }
}
