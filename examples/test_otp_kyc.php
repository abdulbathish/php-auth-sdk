<?php

require_once __DIR__ . '/../vendor/autoload.php';

use MosipAuth\MOSIPAuthenticator;
use MosipAuth\Models\DemographicsModel;
use MosipAuth\Models\IdentityInfo;
use GuzzleHttp\Exception\RequestException;

$config = require __DIR__ . '/../config.php';
$authenticator = new MOSIPAuthenticator($config);

$individualId = '9502435413';
$individualIdType = 'UIN';

echo "=== Step 1: Generate OTP ===" . PHP_EOL;

try {
    $response = $authenticator->genotp(
        $individualId,
        $individualIdType,
        '',
        true,
        true
    );

    $statusCode = $response->getStatusCode();
    echo "Response status code: {$statusCode}" . PHP_EOL;

    $responseBody = json_decode($response->getBody()->getContents(), true);
    $errors = $responseBody['errors'] ?? [];

    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo ($error['errorCode'] ?? '') . " : " . ($error['errorMessage'] ?? '') . PHP_EOL;
        }
        exit(1);
    }

    echo "Response body: " . json_encode($responseBody, JSON_PRETTY_PRINT) . PHP_EOL;
    echo PHP_EOL;

    $otpTransactionId = $responseBody['transactionID'] ?? '';
    if (empty($otpTransactionId)) {
        echo "Error: OTP response does not contain transactionID" . PHP_EOL;
        exit(1);
    }

    echo "=== Step 2: KYC Authentication with OTP ===" . PHP_EOL;

    $demographicsData = new DemographicsModel();
    $demographicsData->name = [new IdentityInfo('eng', 'niraka')];
    $demographicsData->dob = '1987/01/01';
    $demographicsData->gender = [new IdentityInfo('eng', 'male')];

    $otpValue = '111111';
    $txnId = $otpTransactionId;

    echo "Using OTP: {$otpValue}" . PHP_EOL;
    echo "Using Transaction ID: {$txnId}" . PHP_EOL;
    echo PHP_EOL;

    $kycResponse = $authenticator->kyc(
        $individualId,
        $individualIdType,
        $demographicsData,
        $otpValue,
        [],
        true,
        $txnId
    );

    $kycStatusCode = $kycResponse->getStatusCode();
    echo "KYC Response status code: {$kycStatusCode}" . PHP_EOL;

    if ($kycStatusCode !== 200) {
        echo "Request failed with status code {$kycStatusCode}" . PHP_EOL;
        try {
            $kycResponseBody = json_decode($kycResponse->getBody()->getContents(), true);
            $kycErrors = $kycResponseBody['errors'] ?? [];
            if (!empty($kycErrors)) {
                foreach ($kycErrors as $error) {
                    echo ($error['errorCode'] ?? '') . " : " . ($error['errorMessage'] ?? '') . PHP_EOL;
                }
            } else {
                echo "Response body: " . json_encode($kycResponseBody, JSON_PRETTY_PRINT) . PHP_EOL;
            }
        } catch (Exception $e) {
            echo "Error parsing response: " . $e->getMessage() . PHP_EOL;
        }
        exit(1);
    }

    $kycResponseBody = json_decode($kycResponse->getBody()->getContents(), true);
    $kycErrors = $kycResponseBody['errors'] ?? [];

    if (!empty($kycErrors)) {
        foreach ($kycErrors as $error) {
            echo ($error['errorCode'] ?? '') . " : " . ($error['errorMessage'] ?? '') . PHP_EOL;
        }
        exit(1);
    }

    try {
        $decryptedResponse = $authenticator->decryptResponse($kycResponseBody);
        echo "Decrypted response: " . json_encode($decryptedResponse, JSON_PRETTY_PRINT) . PHP_EOL;
    } catch (Exception $e) {
        echo "Error decrypting response: " . $e->getMessage() . PHP_EOL;
        echo "Response body: " . json_encode($kycResponseBody, JSON_PRETTY_PRINT) . PHP_EOL;
        exit(1);
    }

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
    echo "Stack trace: " . $e->getTraceAsString() . PHP_EOL;
    exit(1);
}

