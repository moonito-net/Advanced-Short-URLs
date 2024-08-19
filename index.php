<?php

// Suppress error reporting (consider using error logging in production instead of turning off error reporting)
error_reporting(0);

// Include required files
require_once "config.php";
require_once "lib/function/main.php";

// Initialize the Main class with API credentials and contact email
$main = new Main($apiPublicKey, $apiSecretKey, $contactEmail);

// Process the query parameter 'q' if it is set and valid
if (isset($_GET["q"])) {
    // Sanitize the input using a regex to only allow alphanumeric characters
    $query = $_GET["q"];
    
    if (preg_match("/^[a-zA-Z0-9]*$/", $query)) {
        // Fetch data from the main class using the query
        $json = json_decode($main->get($query), true);

        // If valid redirection data exists, perform the redirection
        if (isset($json['data']['redirection']['to'])) {
            $main->redirect(
                $json['data']['redirection']['to'],
                $json['data']['redirection']['title'] ?? '',
                $json['data']['redirection']['action'] ?? '',
                $json['data']['redirection']['use_javascript'] ?? false
            );
        } else {
            // If no valid redirection, redirect to a 404 page
            $main->redirect(404);
        }
    } else {
        // Invalid 'q' parameter, redirect to 405 (method not allowed)
        $main->redirect(405);
    }
} else {
    // If 'q' is not set, check if the index should be hidden or not
    $hideIndex ? header("HTTP/1.1 403 Forbidden") : $main->redirect(200);
}
