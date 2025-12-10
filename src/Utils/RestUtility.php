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
    private $sslConfig;

    public function __construct($authServerUrl, $authorizationHeaderConstant, $logger, $sslConfig = [])
    {
        $this->authServerUrl = $authServerUrl;
        $this->requestHeaders = [
            'Authorization' => $authorizationHeaderConstant,
            'Content-Type' => 'application/json',
        ];
        $this->logger = $logger;
        $this->sslConfig = $sslConfig;
        
        // Configure SSL options for Guzzle client
        $clientOptions = [];
        if (isset($sslConfig['verify'])) {
            $clientOptions['verify'] = $sslConfig['verify'];
        }
        if (isset($sslConfig['cert'])) {
            $clientOptions['cert'] = $sslConfig['cert'];
        }
        if (isset($sslConfig['ssl_key'])) {
            $clientOptions['ssl_key'] = $sslConfig['ssl_key'];
        }
        if (isset($sslConfig['cafile'])) {
            $clientOptions['verify'] = $sslConfig['cafile'];
        }
        
        $this->client = new Client($clientOptions);
    }

    public function getRequest($pathParams = null, $headers = [], $data = null, $cookies = null)
    {
        $serverUrl = $this->authServerUrl;
        if ($pathParams) {
            $serverUrl .= $pathParams;
        }
        $this->logger->info("Got <GET> Request for URL and Path Params: {$serverUrl}");

        try {
            $requestOptions = [
                'headers' => array_merge($this->requestHeaders, $headers),
                'json' => $data,
                'cookies' => $cookies,
            ];
            
            // Add SSL options if not already set at client level
            if (isset($this->sslConfig['verify']) && !isset($requestOptions['verify'])) {
                $requestOptions['verify'] = $this->sslConfig['verify'];
            }
            
            $response = $this->client->get($serverUrl, $requestOptions);
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
            $requestOptions = [
                'headers' => $headers,
                'json' => $data,
                'cookies' => $cookies,
            ];
            
            // Add SSL options if not already set at client level
            if (isset($this->sslConfig['verify']) && !isset($requestOptions['verify'])) {
                $requestOptions['verify'] = $this->sslConfig['verify'];
            }
            
            $response = $this->client->post($serverUrl, $requestOptions);
            return $response;
        } catch (GuzzleException $e) {
            $this->logger->error("POST Request failed: " . $e->getMessage());
            throw $e;
        }
    }
}

