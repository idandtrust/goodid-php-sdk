<?php

namespace GoodID\Authentication;

interface ResponseHandler
{
    public function handleResponse(GoodIDResponse $gidResponse);
}