<?php

namespace GoodID\Authentication;

use GoodID\Helpers\GoodidSession;

interface ResponseHandler
{
    public function handleResponse(GoodidSession $goodidSession = null, $idToken, array $userInfo);
}