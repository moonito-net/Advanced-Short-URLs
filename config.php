<?php

/**
 * API Key Configuration
 *
 * To use the API, you need to set up your public and secret API keys.
 * Visit https://moonito.net/api for more details.
 *
 * @var string $apiPublicKey Your API Public Key
 * @var string $apiSecretKey Your API Secret Key
 */

 // Enter your API Public Key here
$apiPublicKey = 'API_PUBLIC_KEY';

// Enter your API Secret Key here
$apiSecretKey = 'API_SECRET_KEY';

/**
 * Site Configuration
 * 
 * These settings control various aspects of your site’s behavior.
 * 
 * @var string $contactEmail Your site contact email
 * @var boolean $hideIndex Your site index will redirect to HTTP 403 Forbidden if you enable this
 */

 // Automatically set your contact email based on the site's domain
$contactEmail = 'contact@' . $_SERVER['SERVER_NAME'];

// Set to true if you want the index to be hidden and return HTTP 403
$hideIndex = false;
