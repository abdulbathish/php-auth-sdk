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
        'partner_apikey' => '783367',
        'partner_misp_lk' => 'Vn6deg0RevKVjSgAFYL4O4itSgQ4iDwLOzCLzGWwSxW1CX0gIW',
        'partner_id' => 'authpartner',
    ],
    'mosip_auth_server' => [
        'ida_auth_domain_uri' => 'https://api-internal.sandbox-mosip.oueg.info',
        'ida_auth_url' => 'https://api-internal.sandbox-mosip.oueg.info/idauthentication/v1',
        // SSL Configuration (optional)
        'ssl' => [
            // Set to false to disable SSL verification (only for staging/dev environments)
            // Set to true to use system CA bundle (default)
            // Set to a file path to use a custom CA certificate file
            'verify' => true, // or false for staging, or '/path/to/cacert.pem' for custom CA
            // Optional: Path to CA certificate bundle (alternative to verify)
            // 'cafile' => '/path/to/cacert.pem',
        ],
    ],
    'crypto_encrypt' => [
        'symmetric_key_size' => 256,
        'symmetric_nonce_size' => 128,
        'symmetric_gcm_tag_size' => 128,
        'encrypt_cert_path' => $configDir . '/keys/ida.pem',
        'decrypt_p12_file_path' => $configDir . '/keys/pa.p12',
        'decrypt_p12_file_password' => 'mosip123',
    ],
    'crypto_signature' => [
        'algorithm' => 'RS256',
        'sign_p12_file_path' => $configDir . '/keys/pa.p12',
        'sign_p12_file_password' => 'mosip123',
    ],
    'logging' => [
        'log_file_path' => $configDir . '/authenticator.log',
        'log_format' => '[%s] %s - %s - %s',
        'loglevel' => 'DEBUG',
    ],
];

