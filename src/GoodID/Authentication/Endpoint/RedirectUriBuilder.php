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

namespace GoodID\Authentication\Endpoint;

use GoodID\Helpers\Request\IncomingRequest;
use GoodID\ServiceLocator;
use GoodID\Helpers\GoodIDPartnerConfig;
use GoodID\Authentication\GoodIDSuccessResponse;
use GoodID\Authentication\GoodIDErrorResponse;
use GoodID\Helpers\GoodidSession;
use GoodID\Helpers\Request\TokenRequest;
use Jose\Object\JWSInterface;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestURI;
use GoodID\Exception\GoodIDException;
use GoodID\Exception\ValidationException;
use GoodID\Helpers\Key\RSAPublicKey;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\Helpers\MobileCommunicationServiceInterface;
use GoodID\Authentication\GoodIDResponseInterface;
use GoodID\Helpers\GoodidResult;

class RedirectUriBuilder
{
    /**
     * @var GoodIDPartnerConfig
     */
    protected $goodidPartnerConfig;

    /**
     * @var ServiceLocator
     */
    protected $serviceLocator;

    /**
     * @var string
     */
    protected $state;

    /**
     * @var MobileCommunicationServiceInterface
     */
    protected $mobileCommunicationService;

    /**
     * @param ServiceLocator $serviceLocator
     * @param GoodIDPartnerConfig $goodidPartnerConfig
     */
    public function __construct(
        ServiceLocator $serviceLocator,
        GoodIDPartnerConfig $goodidPartnerConfig
    ) {
        $this->serviceLocator = $serviceLocator;
        $this->goodidPartnerConfig = $goodidPartnerConfig;
    }

    /**
     * @param MobileCommunicationServiceInterface $mobileCommunicationService
     */
    public function setMobileCommunicationService(MobileCommunicationServiceInterface $mobileCommunicationService)
    {
        $this->mobileCommunicationService = $mobileCommunicationService;
    }

    /**
     * @param IncomingRequest $incomingRequest
     * @return GoodIDErrorResponse
     * @throws GoodIDException
     */
    private function generateGoodIDErrorResponse(IncomingRequest $incomingRequest)
    {
        $error = $incomingRequest->getStringParameter('error');

        if (!$error) {
            throw new GoodIDException("Neither code nor error parameter is set.");
        }

        $errorDescription = $incomingRequest->getStringParameter('error_description');

        return new GoodIDErrorResponse($error, $errorDescription);
    }

    /**
     * @return GoodidSession|null
     * @throws \LogicException
     */
    private function getGoodIDSession()
    {
        $goodidSession = null;
        $sessionDataHandler = $this->serviceLocator->getSessionDataHandler();
        $goodidSessionId = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_GOODID_SESSION_ID);

        if ($goodidSessionId !== null) {
            $sessionStore = $this->serviceLocator->getGoodIDSessionStore();

            if ($sessionStore === null) {
                throw new \LogicException('To use any mobilecommunication feature, you must provide a GoodidSessionStore');
            }

            $goodidSession = $this->serviceLocator->getGoodIDSessionStore()->loadGoodidSession($goodidSessionId);
        }

        return $goodidSession;
    }

    /**
     * @param IncomingRequest $incomingRequest
     * @return GoodIDErrorResponse|TokenRequest
     * 
     * @throws GoodIDException
     */
    private function getTokenRequest(IncomingRequest $incomingRequest)
    {
        $authCode = $incomingRequest->getStringParameter('code');

        // Handle error case
        if (!$authCode) {
            return $this->generateGoodIDErrorResponse($incomingRequest);
        }

        $goodIdServerConfig = $this->serviceLocator->getServerConfig();
        $sessionDataHandler = $this->serviceLocator->getSessionDataHandler();
        $usedRedirectUri = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI);
        $requestFactory = $this->serviceLocator->getRequestFactory();

        return $requestFactory->createTokenRequest(
            $goodIdServerConfig,
            $this->goodidPartnerConfig->getClientId(),
            $this->goodidPartnerConfig->getClientSecret(),
            $usedRedirectUri,
            $authCode,
            null
        );
    }

    /**
     * @param IncomingRequest $incomingRequest
     * @return void
     * 
     * @throws GoodIDException
     * @throws ValidationException
     */
    private function validateRequest(IncomingRequest $incomingRequest)
    {
        $stateNonceHandler = $this->serviceLocator->getStateNonceHandler();
        $method = $incomingRequest->getMethod();

        if ($method !== 'GET') {
            throw new GoodIDException("Unexpected request method: $method!");
        }

        if (!$stateNonceHandler->validateState($incomingRequest->getStringParameter('state'))) {
            throw new ValidationException("The received state is invalid.");
        }

        $sessionDataHandler = $this->serviceLocator->getSessionDataHandler();
        $requestSource = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE);
        $usedRedirectUri = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI);

        if (!$requestSource) {
            throw new GoodIDException("Request source is not set in session!");
        }

        if (!$usedRedirectUri) {
            throw new GoodIDException("Redirect uri is not set in session!");
        }
    }

    /**
     * @return array
     * 
     * @throws \Exception
     */
    protected function getRequestObjectAsArray()
    {
        $sessionDataHandler = $this->serviceLocator->getSessionDataHandler();
        $requestSource = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE);
        if (is_array($requestSource)) {
            return $requestSource;
        } elseif (is_string($requestSource) && $requestSource !== OpenIDRequestSource::CONTENT_IS_ENCRYPTED) {
            $downloadedRequestSource = (new OpenIDRequestURI($requestSource))->toArray($this->goodidPartnerConfig->getSigningKey());

            if ($downloadedRequestSource !== OpenIDRequestSource::CONTENT_IS_ENCRYPTED) {
                return $downloadedRequestSource;
            }
        }

        throw new \Exception('The original request object is missing.');
    }

    /**
     * @param TokenRequest $tokenRequest
     * 
     * @return JWSInterface
     */
    private function getIdToken(TokenRequest $tokenRequest)
    {
        $stateNonceHandler = $this->serviceLocator->getStateNonceHandler();

        $tokenRequest->execute();
        $jwe = $tokenRequest->getIdTokenJwe();
        $tokenExtractor = $this->serviceLocator->getTokenExtractor($this->goodidPartnerConfig->getEncryptionKeySet());
        $usedRequestObjectAsArray = $this->getRequestObjectAsArray();

        $requestedMaxAge = isset($usedRequestObjectAsArray['max_age'])
            ? $usedRequestObjectAsArray['max_age']
            : null;

        if (is_object($usedRequestObjectAsArray['claims']['userinfo'])) {
            $usedRequestObjectAsArray['claims']['userinfo'] = [];
        }

        $authTimeRequested = isset($usedRequestObjectAsArray['claims']) && isset($usedRequestObjectAsArray['claims']['id_token']) && is_array($usedRequestObjectAsArray['claims']['id_token']) && isset($usedRequestObjectAsArray['claims']['id_token']['auth_time']['essential']) && $usedRequestObjectAsArray['claims']['id_token']['auth_time']['essential'] === true;
        $authTimeRequested |= isset($usedRequestObjectAsArray['claims']['userinfo']['auth_time']['essential']) && $usedRequestObjectAsArray['claims']['userinfo']['auth_time']['essential'] === true;

        $idToken = $tokenExtractor->extractToken($jwe);
        $idTokenVerifier = $this->serviceLocator->getIdTokenVerifier(
            $this->goodidPartnerConfig->getClientId(),
            $this->goodidPartnerConfig->getSecurityLevel(),
            $requestedMaxAge,
            $authTimeRequested,
            $stateNonceHandler->getCurrentNonce(),
            $idToken->hasClaim('acr') ? $idToken->getClaim('acr') : null
        );
        $idTokenVerifier->verifyIdToken($idToken);

        return $idToken;
    }

    /**
     * @param TokenRequest $tokenRequest
     * @param JWSInterface $idToken
     * @param bool $matchingResponseValidation
     * 
     * @return JWSInterface
     */
    private function getUserinfo(TokenRequest $tokenRequest, JWSInterface $idToken, $matchingResponseValidation)
    {
        $goodIdServerConfig = $this->serviceLocator->getServerConfig();
        $requestFactory = $this->serviceLocator->getRequestFactory();
        $tokenExtractor = $this->serviceLocator->getTokenExtractor($this->goodidPartnerConfig->getEncryptionKeySet());

        $userinfoRequest = $requestFactory->createUserinfoRequest(
            $goodIdServerConfig,
            $tokenRequest->getAccessToken()
        );
        $userinfoRequest->execute();

        $userinfo = $tokenExtractor->extractToken($userinfoRequest->getUserInfoJwe());
        $userinfoVerifier = $this->serviceLocator->getUserinfoVerifier($this->goodidPartnerConfig->getSecurityLevel(), $idToken);
        $userinfoVerifier->verifyUserinfo($userinfo);

        // Matching response validation
        if ($matchingResponseValidation) {
            $usedRequestObjectAsArray = $this->getRequestObjectAsArray();

            if (is_null($usedRequestObjectAsArray)) {
                throw new ValidationException("Matching response validation cannot succeed because the request object was probably encrypted.");
            }

            if (isset($usedRequestObjectAsArray["claims"]) && is_array($usedRequestObjectAsArray["claims"])) {
                /** @var $validator ResponseValidator */
                $validator = $this->serviceLocator->getResponseValidator();
                $validator->validateMatchingResponse($usedRequestObjectAsArray["claims"], $userinfo->getClaims());
            }
        }
        
        return $userinfo;
    }

    /**
     * @param JWSInterface $userinfo
     * @param GoodidSession $goodidSession
     * 
     * @return void
     */
    private function validateAttachments(JWSInterface $userinfo, GoodidSession $goodidSession = null)
    {
        if (!$userinfo->hasClaim(GoodIDSuccessResponse::USERINFO_KEY_ATTACHMENTS)) {
            return;
        }

        if (!$this->mobileCommunicationService) {
            throw new \Exception('Mobile communication service is not set.');
        }

        if (!$goodidSession) {
            throw new \InvalidArgumentException('GoodID Session is not defined.');
        }

        $uploadedAttachments = $this->mobileCommunicationService->getUploadedAttachmentIdsWithHashes($goodidSession);

        if (!$uploadedAttachments) {
            throw new \InvalidArgumentException('Not found any attachment hash in session');
        }

        foreach ($userinfo->getClaim(GoodIDSuccessResponse::USERINFO_KEY_ATTACHMENTS) as $attachmentId => $hash) {
            if (!isset($uploadedAttachments[$attachmentId]) || $uploadedAttachments[$attachmentId] !== $hash) {
                throw new \Exception('Attachment is not in session or has different value:' . $attachmentId);
            }
        }
    }

    /**
     * @param GoodIDSuccessResponse $goodidSuccessResponse
     * 
     * @return GoodIDResponseInterface
     */
    protected function returnResponse(GoodIDSuccessResponse $goodidSuccessResponse)
    {
        return $goodidSuccessResponse;
    }

    /**
     * @param bool $matchingResponseValidation
     * @param IncomingRequest $incomingRequest
     * @param bool $setResultForGoodID
     * 
     * @return GoodIDResponseInterface
     */
    public function handleResponse(
        $matchingResponseValidation = true,
        IncomingRequest $incomingRequest = null,
        $setResultForGoodID = true
    ) {
        try {
            $incomingRequest = $incomingRequest ?: new IncomingRequest();
            $stateNonceHandler = $this->serviceLocator->getStateNonceHandler();
            $sessionDataHandler = $this->serviceLocator->getSessionDataHandler();
            $goodidSession = $this->getGoodIDSession();
            $this->state = $stateNonceHandler->getStateData();

            // Request validation
            $this->validateRequest($incomingRequest);

            $tokenRequest = $this->getTokenRequest($incomingRequest);

            if ($tokenRequest instanceof GoodIDErrorResponse) {
                return $tokenRequest;
            }

            $idToken = $this->getIdToken($tokenRequest);
            $userinfo = $this->getUserinfo($tokenRequest, $idToken, $matchingResponseValidation);

            $this->validateAttachments($userinfo, $goodidSession);
            $this->accessToken = $tokenRequest->getAccessToken();
            $this->pushTokenResponse = $tokenRequest->getPushTokenResponse();

            $response = $this->returnResponse(
                new GoodIDSuccessResponse(
                    $idToken,
                    $userinfo,
                    $this->state,
                    $tokenRequest,
                    $this->goodidPartnerConfig->getSecurityLevel(),
                    $goodidSession
                )
            );

            if ($setResultForGoodID) {
                $response->setResult();
            }

            return $response;
        } catch(\Exception $e) {
            if ($setResultForGoodID) {
                GoodidResult::createFromException($e);
            }

            throw $e;
        } finally {
            $stateNonceHandler->clear();
            $sessionDataHandler->removeAll();
            if ($goodidSession !== null) {
                $this->serviceLocator->getGoodIDSessionStore()->clearGoodidSession($goodidSession->getId());
            }
        }
    }

    /**
     * @return string
     */
    public function getState()
    {
        return $this->state;
    }
}