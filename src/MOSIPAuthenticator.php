<?php

namespace MosipAuth;

use MosipAuth\Models\DemographicsModel;
use MosipAuth\Utils\CryptoUtility;
use MosipAuth\Utils\RestUtility;
use MosipAuth\Utils\Logger;
use Exception;

class MOSIPAuthenticator
{
    private $authRestUtil;
    private $cryptoUtil;
    private $authDomainScheme;
    private $partnerMispLk;
    private $partnerId;
    private $partnerApikey;
    private $idaAuthVersion;
    private $idaAuthRequestIdByController;
    private $idaAuthEnv;
    private $timestampFormat;
    private $authorizationHeaderConstant;
    private $logger;

    public function __construct($config, $logger = null)
    {
        $this->validateConfig($config);
        
        if (!$logger) {
            $this->logger = new Logger(
                $config['logging']['log_file_path'],
                $config['logging']['log_format'],
                $config['logging']['loglevel']
            );
        } else {
            $this->logger = $logger;
        }

        $this->authRestUtil = new RestUtility(
            $config['mosip_auth_server']['ida_auth_url'],
            $config['mosip_auth']['authorization_header_constant'],
            $this->logger
        );

        $this->cryptoUtil = new CryptoUtility(
            $config['crypto_encrypt'],
            $config['crypto_signature'],
            $this->logger
        );

        $this->authDomainScheme = $config['mosip_auth_server']['ida_auth_domain_uri'];
        $this->partnerMispLk = (string)$config['mosip_auth']['partner_misp_lk'];
        $this->partnerId = (string)$config['mosip_auth']['partner_id'];
        $this->partnerApikey = (string)$config['mosip_auth']['partner_apikey'];
        $this->idaAuthVersion = $config['mosip_auth']['ida_auth_version'];
        $this->idaAuthRequestIdByController = [
            'auth' => $config['mosip_auth']['ida_auth_request_demo_id'],
            'kyc' => $config['mosip_auth']['ida_auth_request_kyc_id'],
            'otp' => $config['mosip_auth']['ida_auth_request_otp_id'],
        ];
        $this->idaAuthEnv = $config['mosip_auth']['ida_auth_env'];
        $this->timestampFormat = $config['mosip_auth']['timestamp_format'];
        $this->authorizationHeaderConstant = $config['mosip_auth']['authorization_header_constant'];
    }

    private function validateConfig($config)
    {
        if (empty($config['mosip_auth_server']['ida_auth_url'])) {
            throw new Exception("Config should have 'ida_auth_url' set under [mosip_auth_server] section");
        }
        if (empty($config['mosip_auth_server']['ida_auth_domain_uri'])) {
            throw new Exception("Config should have 'ida_auth_domain_uri' set under [mosip_auth_server] section");
        }
    }

    private function getDefaultBaseRequest($controller, $timestamp, $txnId, $individualId, $individualIdType)
    {
        $timestampObj = $timestamp ? new \DateTime($timestamp) : new \DateTime('now', new \DateTimeZone('UTC'));
        $timestampStr = $timestampObj->format($this->timestampFormat) . '.' . substr($timestampObj->format('u'), 0, 3) . 'Z';
        
        $transactionId = $txnId ?: $this->generateTransactionId();
        
        $id = $this->idaAuthRequestIdByController[$controller] ?? '';
        if (empty($id)) {
            throw new Exception("No id found for controller: {$controller}");
        }

        return [
            'id' => $id,
            'version' => $this->idaAuthVersion,
            'individualId' => $individualId,
            'individualIdType' => $individualIdType,
            'transactionID' => $transactionId,
            'requestTime' => $timestampStr,
        ];
    }

    private function getDefaultAuthRequest($controller, $timestamp = null, $individualId = '', $txnId = '', $consentObtained = false, $idType = 'VID')
    {
        $baseRequest = $this->getDefaultBaseRequest($controller, $timestamp, $txnId, $individualId, $idType);
        
        if ($controller === 'otp') {
            return array_merge($baseRequest, [
                'otpChannel' => [],
                'metadata' => [],
            ]);
        }

        return array_merge($baseRequest, [
            'specVersion' => $this->idaAuthVersion,
            'thumbprint' => $this->cryptoUtil->getEncCertThumbprint(),
            'domainUri' => $this->authDomainScheme,
            'env' => $this->idaAuthEnv,
            'requestedAuth' => [
                'demo' => false,
                'pin' => false,
                'otp' => false,
                'bio' => false,
            ],
            'request' => '',
            'consentObtained' => $consentObtained,
            'requestHMAC' => '',
            'requestSessionKey' => '',
            'metadata' => (object)[],
        ]);
    }

    private function generateTransactionId()
    {
        return str_pad((string)mt_rand(0, 9999999999), 10, '0', STR_PAD_LEFT);
    }

    private function authenticate($controller, $individualId, $demographicData = null, $otpValue = '', $biometrics = [], $consentObtained = false, $individualIdType = null, $txnId = '')
    {
        $this->logger->info("Received Auth Request for demographic.");
        
        $authRequest = $this->getDefaultAuthRequest(
            $controller,
            null,
            $individualId,
            $txnId,
            $consentObtained,
            $individualIdType
        );

        $encryptRequest = [
            'timestamp' => $authRequest['requestTime'],
            'biometrics' => $biometrics ?: [],
            'demographics' => $demographicData ? $demographicData->toArray() : null,
            'otp' => $otpValue ?: '',
        ];

        $encryptRequest = array_filter($encryptRequest, function ($value) {
            if (is_array($value)) {
                return !empty($value);
            }
            return $value !== '' && $value !== null;
        });

        try {
            list($encryptedAuthData, $encryptedAesKey, $encAuthDataHash) = $this->cryptoUtil->encryptAuthData($encryptRequest);
            
            $authRequest['request'] = $encryptedAuthData;
            $authRequest['requestSessionKey'] = $encryptedAesKey;
            $authRequest['requestHMAC'] = $encAuthDataHash;
        } catch (Exception $e) {
            $this->logger->error("Failed to Encrypt Auth Data. Error Message: " . $e->getMessage());
            throw $e;
        }

        $pathParams = implode('/', array_map('urlencode', [
            $controller,
            $this->partnerMispLk,
            $this->partnerId,
            $this->partnerApikey,
        ]));

        $fullRequestJson = json_encode($authRequest);
        $this->logger->debug("Full request JSON: {$fullRequestJson}");

        try {
            $signatureHeader = [
                'Signature' => $this->cryptoUtil->signAuthRequestData($fullRequestJson),
            ];
        } catch (Exception $e) {
            $this->logger->error("Failed to Sign Auth Data. Error Message: " . $e->getMessage());
            throw $e;
        }

        $this->logger->debug("Posting to {$pathParams}");
        $response = $this->authRestUtil->postRequest(
            $pathParams,
            $signatureHeader,
            $authRequest
        );
        
        $this->logger->info("Auth Request for Demographic Completed.");
        return $response;
    }

    public function auth($individualId, $individualIdType, $demographicData = null, $otpValue = '', $biometrics = [], $consent = false, $txnId = '')
    {
        return $this->authenticate(
            'auth',
            $individualId,
            $demographicData,
            $otpValue,
            $biometrics,
            $consent,
            $individualIdType,
            $txnId
        );
    }

    public function kyc($individualId, $individualIdType, $demographicData = null, $otpValue = '', $biometrics = [], $consent = false, $txnId = '')
    {
        return $this->authenticate(
            'kyc',
            $individualId,
            $demographicData,
            $otpValue,
            $biometrics,
            $consent,
            $individualIdType,
            $txnId
        );
    }

    public function genotp($individualId, $individualIdType, $txnId = '', $email = false, $phone = false)
    {
        $channels = [];
        if ($email) {
            $channels[] = 'email';
        }
        if ($phone) {
            $channels[] = 'phone';
        }
        
        if (empty($channels)) {
            $errMsg = "At least one OTP channel (email or phone) must be specified";
            $this->logger->error($errMsg);
            throw new Exception($errMsg);
        }

        $this->logger->info("Received OTP Generation Request.");

        $otpRequest = $this->getDefaultAuthRequest(
            'otp',
            null,
            $individualId,
            $txnId,
            false,
            $individualIdType
        );
        $otpRequest['otpChannel'] = $channels;

        $pathParams = implode('/', array_map('urlencode', [
            'otp',
            $this->partnerMispLk,
            $this->partnerId,
            $this->partnerApikey,
        ]));

        $fullRequestJson = json_encode($otpRequest);
        $this->logger->debug("Full request JSON: {$fullRequestJson}");

        try {
            $signatureHeader = [
                'Signature' => $this->cryptoUtil->signAuthRequestData($fullRequestJson),
            ];
        } catch (Exception $e) {
            $this->logger->error("Failed to Sign OTP Request. Error Message: " . $e->getMessage());
            throw $e;
        }

        $this->logger->debug("Posting to {$pathParams}");
        $response = $this->authRestUtil->postRequest(
            $pathParams,
            $signatureHeader,
            $otpRequest
        );

        $this->logger->info("OTP Generation Request Completed.");
        return $response;
    }

    public function decryptResponse($responseBody)
    {
        $r = $responseBody['response'] ?? null;
        if (!$r) {
            throw new Exception("Response body does not contain 'response' field");
        }
        
        $sessionKeyB64 = $r['sessionKey'] ?? null;
        $identityB64 = $r['identity'] ?? null;
        
        if (!$sessionKeyB64 || !$identityB64) {
            throw new Exception("Response missing sessionKey or identity");
        }
        
        $decrypted = $this->cryptoUtil->decryptAuthData($sessionKeyB64, $identityB64);
        return $decrypted;
    }
}

