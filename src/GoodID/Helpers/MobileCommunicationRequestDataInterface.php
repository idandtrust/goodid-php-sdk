<?php

namespace GoodID\Helpers;

interface MobileCommunicationRequestDataInterface
{
    public function getInstructions();
    public function getUrlConfigs();
    public function getGoodIDSession();
    public function getSessionReadUri();
    public function setDeviceId($deviceId);
    public function getDeviceId();
}
