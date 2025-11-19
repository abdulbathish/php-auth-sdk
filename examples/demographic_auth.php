<?php

require_once __DIR__ . '/../vendor/autoload.php';

use MosipAuth\MOSIPAuthenticator;
use MosipAuth\Models\DemographicsModel;
use MosipAuth\Models\IdentityInfo;
use GuzzleHttp\Exception\RequestException;

$config = require __DIR__ . '/../config.php';
$authenticator = new MOSIPAuthenticator($config);

$demographicsData = new DemographicsModel();
$demographicsData->name = [new IdentityInfo('eng', 'niraka')];
$demographicsData->dob = '1987/01/01';
$demographicsData->gender = [new IdentityInfo('eng', 'male')];

echo "Demographics data: " . json_encode($demographicsData->toArray(), JSON_PRETTY_PRINT) . PHP_EOL;

try {
    $response = $authenticator->kyc(
        '9502435413',
        'UIN',
        $demographicsData,
        '',
        [],
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
            echo "Response text: " . $response->getBody()->getContents() . PHP_EOL;
        }
        exit(1);
    }

    $responseBody = json_decode($response->getBody()->getContents(), true);
    if ($responseBody === null) {
        echo "Error: Response body is null" . PHP_EOL;
        exit(1);
    }

    $errors = $responseBody['errors'] ?? [];
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo ($error['errorCode'] ?? '') . " : " . ($error['errorMessage'] ?? '') . PHP_EOL;
        }
        exit(1);
    }

    try {
        $decryptedResponse = $authenticator->decryptResponse($responseBody);
        echo "Decrypted response: " . json_encode($decryptedResponse, JSON_PRETTY_PRINT) . PHP_EOL;
    } catch (Exception $e) {
        echo "Error decrypting response: " . $e->getMessage() . PHP_EOL;
        echo "Response body: " . json_encode($responseBody, JSON_PRETTY_PRINT) . PHP_EOL;
        exit(1);
    }
} catch (GuzzleHttp\Exception\RequestException $e) {
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
        echo "Stack trace: " . $e->getTraceAsString() . PHP_EOL;
        exit(1);
    }

