<?php

namespace MosipAuth\Utils;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class RestUtility
{
    private $authServerUrl;
    private $requestHeaders;
    private $logger;
    private $client;

    public function __construct($authServerUrl, $authorizationHeaderConstant, $logger)
    {
        $this->authServerUrl = $authServerUrl;
        $this->requestHeaders = [
            'Authorization' => $authorizationHeaderConstant,
            'Content-Type' => 'application/json',
        ];
        $this->logger = $logger;
        $this->client = new Client();
    }

    public function getRequest($pathParams = null, $headers = [], $data = null, $cookies = null)
    {
        $serverUrl = $this->authServerUrl;
        if ($pathParams) {
            $serverUrl .= $pathParams;
        }
        $this->logger->info("Got <GET> Request for URL and Path Params: {$serverUrl}");

        try {
            $response = $this->client->get($serverUrl, [
                'headers' => array_merge($this->requestHeaders, $headers),
                'json' => $data,
                'cookies' => $cookies,
            ]);
            return $response;
        } catch (GuzzleException $e) {
            $this->logger->error("GET Request failed: " . $e->getMessage());
            throw $e;
        }
    }

    public function postRequest($pathParams = null, $additionalHeaders = [], $data = null, $cookies = null)
    {
        $serverUrl = $this->authServerUrl;
        if ($pathParams) {
            if (substr($serverUrl, -1) !== '/') {
                $serverUrl .= '/';
            }
            $serverUrl .= $pathParams;
        }

        $headers = array_merge($this->requestHeaders, $additionalHeaders);

        $this->logger->info("Got <POST> Request for URL: {$this->authServerUrl}");
        $this->logger->debug("Final request route = {$serverUrl}");
        $this->logger->debug("Request Headers = " . json_encode($headers));

        try {
            $response = $this->client->post($serverUrl, [
                'headers' => $headers,
                'json' => $data,
                'cookies' => $cookies,
            ]);
            return $response;
        } catch (GuzzleException $e) {
            $this->logger->error("POST Request failed: " . $e->getMessage());
            throw $e;
        }
    }
}

