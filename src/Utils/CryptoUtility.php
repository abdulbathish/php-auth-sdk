<?php

namespace MosipAuth\Utils;

use Exception;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\File\X509;

class CryptoUtility
{
    private $encryptCertObj;
    private $decryptPrivateKey;
    private $signPrivateKey;
    private $signCert;
    private $encCertThumbprint;
    private $symmetricKeySize;
    private $symmetricNonceSize;
    private $symmetricGcmTagSize;
    private $algorithm;
    private $logger;

    public function __construct($encryptConfig, $signConfig, $logger)
    {
        $this->logger = $logger;
        
        $this->encryptCertObj = $this->getCertificateObj($encryptConfig['encrypt_cert_path'], $logger);
        
        $p12Data = $this->getPrivKeyCert($encryptConfig['decrypt_p12_file_path'], $encryptConfig['decrypt_p12_file_password'], $logger);
        $this->decryptPrivateKey = $p12Data['private_key'];
        
        $signP12Data = $this->getPrivKeyCert($signConfig['sign_p12_file_path'], $signConfig['sign_p12_file_password'], $logger);
        $this->signPrivateKey = $signP12Data['private_key'];
        $this->signCert = $signP12Data['certificate'];
        
        $x509 = new X509();
        $certObj = $x509->loadX509($this->encryptCertObj);
        $certDerBin = $x509->saveX509($certObj, X509::FORMAT_DER);
        
        $thumbprint = hash('sha256', $certDerBin, true);
        $this->encCertThumbprint = str_replace(['+', '/'], ['-', '_'], base64_encode($thumbprint));
        
        $this->symmetricKeySize = intval($encryptConfig['symmetric_key_size'] / 8);
        $this->symmetricNonceSize = intval($encryptConfig['symmetric_nonce_size'] / 8);
        $this->symmetricGcmTagSize = intval($encryptConfig['symmetric_gcm_tag_size'] / 8);
        $this->algorithm = $signConfig['algorithm'];
    }

    private function getCertificateObj($certPath, $logger)
    {
        $logger->info("Creating certificate Object for the file Path: {$certPath}");
        
        if (!file_exists($certPath)) {
            throw new Exception("Certificate file not found: {$certPath}");
        }
        
        $certContent = file_get_contents($certPath);
        $cert = openssl_x509_read($certContent);
        
        if ($cert === false) {
            throw new Exception("Error reading certificate file: {$certPath}");
        }
        
        $logger->info("Certificate Object Creation successful.");
        return $certContent;
    }

    private function getPrivKeyCert($p12FilePath, $p12FilePass, $logger)
    {
        $logger->info("Reading P12 file. File Path: {$p12FilePath}");
        
        if (!file_exists($p12FilePath)) {
            throw new Exception("P12 file not found: {$p12FilePath}");
        }
        
        $p12Content = file_get_contents($p12FilePath);
        $certs = [];
        
        if (!openssl_pkcs12_read($p12Content, $certs, $p12FilePass)) {
            throw new Exception("Error loading P12 file: {$p12FilePath}");
        }
        
        return [
            'private_key' => $certs['pkey'],
            'certificate' => $certs['cert'],
            'extracerts' => $certs['extracerts'] ?? [],
        ];
    }

    private function asymmetricEncrypt($aesRandomKey)
    {
        $this->logger->debug("Encrypting the AES Random Key.");
        
        try {
            $x509 = new X509();
            $cert = $x509->loadX509($this->encryptCertObj);
            $publicKey = $x509->getPublicKey();
            
            $publicKey = $publicKey->withHash('sha256')->withMGFHash('sha256')->withPadding(RSA::ENCRYPTION_OAEP);
            
            $encrypted = $publicKey->encrypt($aesRandomKey);
            return $encrypted;
        } catch (Exception $e) {
            throw new Exception("Failed to encrypt AES key: " . $e->getMessage());
        }
    }

    private function asymmetricDecrypt($encryptedData)
    {
        $this->logger->debug("Asymmetric Decryption");
        
        try {
            $rsa = RSA::loadPrivateKey($this->decryptPrivateKey);
            $rsa = $rsa->withHash('sha256')->withMGFHash('sha256')->withPadding(RSA::ENCRYPTION_OAEP);
            
            $decrypted = $rsa->decrypt($encryptedData);
            if ($decrypted === false) {
                throw new Exception("Decryption returned false");
            }
            return $decrypted;
        } catch (Exception $e) {
            throw new Exception("Failed to decrypt session key: " . $e->getMessage());
        }
    }

    private function symmetricEncrypt($data, $key)
    {
        $this->logger->debug("Encrypting the Auth Data using AES Key.");
        
        $iv = random_bytes($this->symmetricNonceSize);
        $tag = '';
        
        $encrypted = openssl_encrypt(
            $data,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($encrypted === false) {
            throw new Exception("Failed to encrypt data with AES-GCM");
        }
        
        return $encrypted . $tag . $iv;
    }

    private function symmetricDecrypt($data, $key)
    {
        $this->logger->debug("Decrypting the Auth Data using AES Key.");
        
        $lenIv = $this->symmetricNonceSize;
        $lenTag = $this->symmetricGcmTagSize;
        
        $iv = substr($data, -$lenIv);
        $tag = substr($data, -($lenTag + $lenIv), $lenTag);
        $encData = substr($data, 0, -($lenTag + $lenIv));
        
        $decrypted = openssl_decrypt(
            $encData,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($decrypted === false) {
            throw new Exception("Failed to decrypt data with AES-GCM");
        }
        
        return $decrypted;
    }

    public function encryptAuthData($authData)
    {
        $this->logger->info("Request for Auth Data Encryption.");
        
        if (is_array($authData)) {
            $authDataBytes = json_encode($authData);
        } elseif (is_string($authData)) {
            $authDataBytes = $authData;
        } else {
            throw new Exception("Unrecognised type");
        }
        
        try {
            $aesKey = random_bytes($this->symmetricKeySize);
            $encryptedAuthData = $this->symmetricEncrypt($authDataBytes, $aesKey);
            $encryptedAuthB64Data = str_replace(['+', '/'], ['-', '_'], base64_encode($encryptedAuthData));
            
            $this->logger->info("Generating AES Key and encrypting Auth Data Completed.");
            
            $encryptedAesKey = $this->asymmetricEncrypt($aesKey);
            $encryptedAesKeyB64 = str_replace(['+', '/'], ['-', '_'], base64_encode($encryptedAesKey));
            
            $this->logger->info("Encrypting Random AES Key Completed.");
            
            $authDataHash = strtoupper(hash('sha256', $authDataBytes));
            $encAuthDataHash = $this->symmetricEncrypt($authDataHash, $aesKey);
            $encAuthDataHashB64 = str_replace(['+', '/'], ['-', '_'], base64_encode($encAuthDataHash));
            
            $this->logger->info("Generation of SHA256 Hash for the Auth Data completed.");
            
            return [
                $encryptedAuthB64Data,
                $encryptedAesKeyB64,
                $encAuthDataHashB64,
            ];
        } catch (Exception $e) {
            $this->logger->error("Error encrypting Auth Data. Error Message: " . $e->getMessage());
            throw $e;
        }
    }

    public function decryptAuthData($sessionKeyB64, $encryptedIdentityB64)
    {
        $sessionKeyB64Padded = $this->b64pad($sessionKeyB64);
        $encryptedIdentityB64Padded = $this->b64pad($encryptedIdentityB64);
        
        $sessionKey = base64_decode(str_replace(['-', '_'], ['+', '/'], $sessionKeyB64Padded));
        $encryptedIdentity = base64_decode(str_replace(['-', '_'], ['+', '/'], $encryptedIdentityB64Padded));
        
        $symKey = $this->asymmetricDecrypt($sessionKey);
        $identity = $this->symmetricDecrypt($encryptedIdentity, $symKey);
        
        return json_decode($identity, true);
    }

    public function signAuthRequestData($authRequestData)
    {
        $this->logger->info("Request for Sign Auth Request Data.");
        
        try {
            $x509 = new X509();
            $cert = $x509->loadX509($this->signCert);
            
            $certPem = $this->signCert;
            $certBase64 = base64_encode($certPem);
            $certBase64 = chunk_split($certBase64, 76, "\n");
            $certBase64 = rtrim($certBase64, "\n");
            
            $protectedHeader = [
                'alg' => $this->algorithm,
                'x5c' => [$certBase64],
            ];
            
            $certDer = $x509->saveX509($cert, X509::FORMAT_DER);
            $thumbprint = hash('sha256', $certDer, true);
            $kid = base64_encode($thumbprint);
            
            $protectedHeaderJson = json_encode($protectedHeader, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $protectedHeaderB64 = $this->base64urlEncode($protectedHeaderJson);
            
            $payloadB64 = $this->base64urlEncode($authRequestData);
            
            $signatureInput = $protectedHeaderB64 . '.' . $payloadB64;
            
            $privateKey = RSA::loadPrivateKey($this->signPrivateKey);
            $privateKey = $privateKey->withHash('sha256')->withPadding(RSA::SIGNATURE_PKCS1);
            
            $signature = $privateKey->sign($signatureInput);
            
            $signatureB64 = $this->base64urlEncode($signature);
            
            $jwsSignature = $protectedHeaderB64 . '..' . $signatureB64;
            
            $this->logger->info("Generation for JWS Signature completed.");
            return $jwsSignature;
        } catch (Exception $e) {
            $this->logger->error("Error Signing Auth Data. Error Message: " . $e->getMessage());
            throw $e;
        }
    }
    
    private function base64urlEncode($data)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    public function getEncCertThumbprint()
    {
        return $this->encCertThumbprint;
    }

    private function b64pad($s)
    {
        $pad = (4 - strlen($s) % 4) % 4;
        return $s . str_repeat('=', $pad);
    }
}

