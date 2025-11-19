# MOSIP Authentication SDK for PHP

PHP SDK for MOSIP (Modular Open Source Identity Platform) Authentication Service. This library provides a simple interface to interact with MOSIP's authentication APIs, enabling demographic authentication, KYC verification, and OTP generation.

## Features

- **Demographic Authentication** - Authenticate individuals using demographic data (name, DOB, gender, etc.)
- **KYC Authentication** - Know Your Customer verification with demographic and biometric data
- **OTP Generation** - Generate OTP via email or phone
- **Response Decryption** - Automatically decrypt and parse API responses
- **JWS Signing** - Secure request signing using RS256
- **Encryption** - RSA/OAEP and AES-256-GCM encryption support

## Requirements

- PHP >= 7.4
- OpenSSL extension
- JSON extension
- cURL extension

## Installation

### Install via Composer (Recommended)

The package is available on [Packagist](https://packagist.org/packages/mosip/php-auth-sdk):

```bash
composer require mosip/php-auth-sdk
```

### Manual Installation

1. Clone this repository:
```bash
git clone https://github.com/abdulbathish/php-auth-sdk.git
cd php-auth-sdk
```

2. Install dependencies:
```bash
composer install
```

## Configuration

Create a `config.php` file in the root directory:

```php
<?php

$configDir = dirname(__FILE__);

return [
    'mosip_auth' => [
        'timestamp_format' => 'Y-m-d\TH:i:s',
        'ida_auth_version' => '1.0',
        'ida_auth_request_demo_id' => 'mosip.identity.auth',
        'ida_auth_request_kyc_id' => 'mosip.identity.kyc',
        'ida_auth_request_otp_id' => 'mosip.identity.otp',
        'ida_auth_env' => 'Staging',
        'authorization_header_constant' => 'Authorization',
        'partner_apikey' => 'YOUR_API_KEY',
        'partner_misp_lk' => 'YOUR_MISP_LK',
        'partner_id' => 'YOUR_PARTNER_ID',
    ],
    'mosip_auth_server' => [
        'ida_auth_domain_uri' => 'https://api-internal.YOUR_DOMAIN',
        'ida_auth_url' => 'https://api-internal.YOUR_DOMAIN/idauthentication/v1',
    ],
    'crypto_encrypt' => [
        'symmetric_key_size' => 256,
        'symmetric_nonce_size' => 128,
        'symmetric_gcm_tag_size' => 128,
        'encrypt_cert_path' => $configDir . '/keys/ida.pem',
        'decrypt_p12_file_path' => $configDir . '/keys/pa.p12',
        'decrypt_p12_file_password' => 'YOUR_P12_PASSWORD',
    ],
    'crypto_signature' => [
        'algorithm' => 'RS256',
        'sign_p12_file_path' => $configDir . '/keys/pa.p12',
        'sign_p12_file_password' => 'YOUR_P12_PASSWORD',
    ],
    'logging' => [
        'log_file_path' => $configDir . '/authenticator.log',
        'log_format' => '[%s] %s - %s - %s',
        'loglevel' => 'DEBUG',
    ],
];
```

Place your certificate files in the `keys/` directory:
- `ida.pem` - IDA certificate for encryption
- `pa.p12` - Partner certificate for signing and decryption

## Usage

### Basic Authentication (KYC)

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use MosipAuth\MOSIPAuthenticator;
use MosipAuth\Models\DemographicsModel;
use MosipAuth\Models\IdentityInfo;

$config = require __DIR__ . '/config.php';
$authenticator = new MOSIPAuthenticator($config);

$demographicsData = new DemographicsModel();
$demographicsData->name = [new IdentityInfo('eng', 'John Doe')];
$demographicsData->dob = '1990/01/01';
$demographicsData->gender = [new IdentityInfo('eng', 'male')];

$response = $authenticator->kyc(
    '9502435413',
    'UIN',
    $demographicsData,
    '',
    [],
    true
);

if ($response->getStatusCode() === 200) {
    $responseBody = json_decode($response->getBody()->getContents(), true);
    $decryptedResponse = $authenticator->decryptResponse($responseBody);
    print_r($decryptedResponse);
}
```

### OTP Generation

```php
$response = $authenticator->genotp(
    '9502435413',
    'UIN',
    '',
    true,  // email
    true   // phone
);

$responseBody = json_decode($response->getBody()->getContents(), true);
$transactionId = $responseBody['transactionID'];
```

### Authentication with OTP

```php
$response = $authenticator->kyc(
    '9502435413',
    'UIN',
    $demographicsData,
    '123456',  // OTP value
    [],
    true,
    $transactionId  // Transaction ID from OTP generation
);
```

## API Reference

### MOSIPAuthenticator

#### `__construct($config, $logger = null)`
Initialize the authenticator with configuration.

#### `auth($individualId, $individualIdType, $demographicData = null, $otpValue = '', $biometrics = [], $consent = false, $txnId = '')`
Perform demographic authentication.

#### `kyc($individualId, $individualIdType, $demographicData = null, $otpValue = '', $biometrics = [], $consent = false, $txnId = '')`
Perform KYC authentication.

#### `genotp($individualId, $individualIdType, $txnId = '', $email = false, $phone = false)`
Generate OTP via email or phone.

#### `decryptResponse($responseBody)`
Decrypt and parse the API response.

## Models

### DemographicsModel

Represents demographic data for authentication:
- `name` - Array of IdentityInfo
- `dob` - Date of birth (format: YYYY/MM/DD)
- `gender` - Array of IdentityInfo
- `phoneNumber` - Phone number
- `emailId` - Email address
- `addressLine1`, `addressLine2`, `addressLine3` - Address lines
- `location1`, `location2`, `location3` - Location information
- `postalCode` - Postal code
- `fullAddress` - Full address

### IdentityInfo

Represents language-value pairs:
- `language` - Language code (e.g., 'eng', 'ara')
- `value` - The actual value

## License

Mozilla Public License Version 2.0

## Author

Abdul Bathish

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
