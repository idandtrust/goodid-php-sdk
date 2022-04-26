<?php

namespace GoodID\Helpers;

interface MobileCommunicationServiceInterface
{
    public function getMobileInstructions(GoodidSession $session);
    public function getMobileUrlConfigs(GoodidSession $session);
    public function createRequest(MobileCommunicationRequestDataInterface $requestData, array &$queryParams);
    public function getUploadedAttachmentIdsWithHashes(GoodidSession $session);
    public function getAuthenticatedGoodidSession();
}
