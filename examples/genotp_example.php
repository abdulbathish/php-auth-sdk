<?php

require_once __DIR__ . '/../vendor/autoload.php';

use MosipAuth\MOSIPAuthenticator;
use GuzzleHttp\Exception\RequestException;

$config = require __DIR__ . '/../config.php';
$authenticator = new MOSIPAuthenticator($config);

try {
    $response = $authenticator->genotp(
        '9502435413',
        'UIN',
        '',
        false,
        true
    );

    $statusCode = $response->getStatusCode();
    echo "Response status code: {$statusCode}" . PHP_EOL;

    if ($statusCode !== 200) {
        echo "Request failed with status code {$statusCode}" . PHP_EOL;
        try {
            $responseBody = json_decode($response->getBody()->getContents(), true);
            $errors = $responseBody['errors'] ?? [];
            if (!empty($errors)) {
                foreach ($errors as $error) {
                    echo ($error['errorCode'] ?? '') . " : " . ($error['errorMessage'] ?? '') . PHP_EOL;
                }
            } else {
                echo "Response body: " . json_encode($responseBody, JSON_PRETTY_PRINT) . PHP_EOL;
            }
        } catch (Exception $e) {
            echo "Error parsing response: " . $e->getMessage() . PHP_EOL;
        }
        exit(1);
    }

    $responseBody = json_decode($response->getBody()->getContents(), true);
    echo "OTP Response: " . json_encode($responseBody, JSON_PRETTY_PRINT) . PHP_EOL;
} catch (RequestException $e) {
    $response = $e->getResponse();
    if ($response) {
        $responseBody = json_decode($response->getBody()->getContents(), true);
        echo "Error: " . $e->getMessage() . PHP_EOL;
        echo "Full error response: " . json_encode($responseBody, JSON_PRETTY_PRINT) . PHP_EOL;
    } else {
        echo "Error: " . $e->getMessage() . PHP_EOL;
    }
    exit(1);
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . PHP_EOL;
    exit(1);
}

