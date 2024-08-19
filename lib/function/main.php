<?php

class Main extends Aes
{
    private $apiUrl;
    private $apiPublicKey;
    private $apiSecretKey;

    public function __construct($apiPublicKey, $apiSecretKey, $contactEmail)
    {
        $this->apiUrl = "https://moonito.net/";
        $this->apiPublicKey = $apiPublicKey;
        $this->apiSecretKey = $apiSecretKey;
        $this->contactEmail = $contactEmail ?? 'contact@' . $_SERVER['SERVER_NAME'];
    }

    public function ipAddress()
    {
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
            $_SERVER['HTTP_CLIENT_IP'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
        }
        $client  = @$_SERVER['HTTP_CLIENT_IP'];
        $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
        $remote  = $_SERVER['REMOTE_ADDR'];

        if(filter_var($client, FILTER_VALIDATE_IP)) {
            $ip = $client;
        } elseif(filter_var($forward, FILTER_VALIDATE_IP)) {
            $ip = $forward;
        } else {
            $ip = $remote;
        }

        return $ip;
    }

    public function get($slug)
    {
        $retryingCurl = 1;
        $query = array(
            'slug' => $slug,
            'ip' => $this->ipAddress(),
            'ua' => urlencode($_SERVER['HTTP_USER_AGENT']),
            'events' => urlencode($_SERVER['REQUEST_URI']),
        );
        while ($retryingCurl <= 5) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->apiUrl . "api/v1/shortlink?" . http_build_query($query));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
            curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'X-Public-Key: ' . $this->apiPublicKey,
                'X-Secret-Key: ' . $this->apiSecretKey,
            ]);

            $response = curl_exec($ch);
            if ($response) {
                return $response;
            }

            $retryingCurl++;
        }

        return false;
    }

    public function redirect($to, $title = null, $action = 'direct', $useJs = false)
    {
        $message = [];

        if(is_numeric($to)) {
            $errorInfo = $this->getHttpErrorInfo($to);
            header("HTTP/1.1 {$to} {$errorInfo[0]}");
            $message = $to == '200' ?
                $this->getSuccessPageMessage('Welcome to ' . $_SERVER['HTTP_HOST'] . '!') :
                $this->getErrorPageMessage($errorInfo[0], $errorInfo[1]);

            echo $this->respondHtml($message);
            exit();
        }

        if($to == 'Server Not Responding') {
            ob_start();
            sleep(3600);
            ob_end_clean();
            exit();
        }

        if($action == 'iframe') {
            echo $this->iframe($to, $title);
            exit();
        }

        if($action == 'loading') {
            $this->loadContent($to);
            exit();
        }

        if($useJs) {
            echo $this->redirectWithJs($to, $title);
            exit();
        }

        header("Location: " . $to, TRUE, 302);
        exit();
    }

    private function iframe($to, $title)
    {
        $html = '<title>' . $title . '</title> <iframe src="' . $to . '" width="100%" height="100%" align="left"></iframe> <style> body { padding: 0; margin: 0; } iframe { margin: 0; padding: 0; border: 0; } </style>';

        return $this->obfuscateHtml($html);
    }

    private function loadContent($to)
    {
        // Options
        $options = ['ssl' => ['verify_peer' => FALSE, 'verify_peer_name' => FALSE], 'http' => ['header' => 'User-Agent: ' . $_SERVER['HTTP_USER_AGENT']]];

        // Load Content
        if (filter_var($to, FILTER_VALIDATE_URL)) {
            echo str_replace('<head>', '<head><base href="' . $to . '" />', file_get_contents($to, FALSE, stream_context_create($options)));
        } elseif (file_exists($to)) {
            if (pathinfo($to, PATHINFO_EXTENSION) == 'php') {
                require_once($to);
            } else {
                echo file_get_contents($to, FALSE, stream_context_create($options));
            }
        } else {
            $this->redirect(404);
        }
    }

    private function redirectWithJs($to, $title)
    {
        $key = '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvxyz';
        $nBits = 256;
        $ciphertext = AesCtr::encrypt($to . md5(time()), $key, $nBits);

        $html = '
        <html lang="en">
            <head>
                <title>' . $title . '</title>
                <script src="lib/js/aes.min.js"></script>
                <script>
                    const aes2p = (\'' . $key . '\');
                    const aes2t = \'' . $ciphertext . '\';
                    const output = Aes.Ctr.decrypt(aes2p, aes2t, ' . $nBits . ');
                    document.write(output)
                </script>
            </head>
            <body style="display: none">
            </body>
            <script>
            function xGtd5Rgt() {
                document.getElementsByTagName("html")[0].innerHTML = \'<meta http-equiv="refresh" content="0;url=' . $to . '" />\';
            }
            function tYfatY7t(){
                let cookieEnabled;
                let webdriver;
                if(navigator.cookieEnabled === true){
                    cookieEnabled = true;
                } else {
                    cookieEnabled = false;
                } if (navigator.webdriver === true){
                    webdriver = true;
                } else {
                    webdriver = false;
                }
                if(cookieEnabled === true && webdriver === false){
                    return false;
                } else {
                    return true;
                }
            }
            if(tYfatY7t() === false){
                xGtd5Rgt();
            }
            </script>
        </html>';

        return $this->obfuscateHtml($html);
    }

    private function getErrorPageMessage($head, $description)
    {
        return [
            "title" => $_SERVER['SERVER_NAME'],
            "head" => $head,
            "description" => $description,
            "contact" => $this->contactEmail
        ];
    }

    private function getSuccessPageMessage($head)
    {
        return [
            "title" => $_SERVER['SERVER_NAME'],
            "head" => $head,
            "description" => 'We\'re glad you\'re here. If you have any questions or need assistance, we\'re here to help. Thank you for visiting!',
            "contact" => $this->contactEmail
        ];
    }

    private function respondHtml($message)
    {
        $getRespond = file_get_contents("template/message.html");
        $getRespond = str_replace("{title}", @$message["title"], $getRespond);
        $getRespond = str_replace("{head}", @$message["head"], $getRespond);
        $getRespond = str_replace("{description}", @$message["description"], $getRespond);
        $getRespond = str_replace("{contact}", @$message["contact"], $getRespond);
        return $this->obfuscateHtml($getRespond);
    }

    private function obfuscateHtml($html) {
        $encodedHtml = base64_encode($html);
    
        $key = rand(1, 255);
        $xor_encoded = '';
        foreach (str_split($encodedHtml) as $char) {
            $xor_encoded .= chr(ord($char) ^ $key);
        }
    
        $doubleEncoded = base64_encode($xor_encoded);
        $chunks = str_split($doubleEncoded, rand(10, 30));
    
        $randomVarName = 'v_' . bin2hex(random_bytes(5));
        $randomFuncName1 = 'f_' . bin2hex(random_bytes(5));
        $randomFuncName2 = 'f_' . bin2hex(random_bytes(5));
        $randomKeyVar = 'k_' . bin2hex(random_bytes(5));
        
        $obfuscatedHtml = '<script>(function(){';
        $obfuscatedHtml .= 'var ' . $randomKeyVar . '=' . $key . ';';
        $obfuscatedHtml .= 'var ' . $randomVarName . '=["' . implode('","', $chunks) . '"];';
        $obfuscatedHtml .= 'function ' . $randomFuncName1 . '(){var d="";for(var i=0;i<' . $randomVarName . '.length;i++){d+=' . $randomVarName . '[i];}return atob(d);}';
        $obfuscatedHtml .= 'function ' . $randomFuncName2 . '(){var e=' . $randomFuncName1 . '(),r="";for(var i=0;i<e.length;i++){r+=String.fromCharCode(e.charCodeAt(i)^' . $randomKeyVar . ');}';
        $obfuscatedHtml .= 'document.write(atob(r));}';
        $obfuscatedHtml .= $randomFuncName2 . '();})();</script>';
        $obfuscatedHtml = str_replace(array("\n", "\r", "\t"), '', $obfuscatedHtml);
    
        return $obfuscatedHtml;
    }

    private function getAllHttpStatusCodesInfo() {
        return [
            100 => ["Continue", "The server has received the request headers and the client should proceed to send the request body."],
            101 => ["Switching Protocols", "The requester has asked the server to switch protocols."],
            102 => ["Processing", "The server has received and is processing the request, but no response is available yet."],
            200 => ["OK", "The request was successful."],
            201 => ["Created", "The request was successful, and a resource was created."],
            202 => ["Accepted", "The request was accepted for processing, but the processing has not been completed."],
            203 => ["Non-Authoritative Information", "The server successfully processed the request but is returning information that may be from another source."],
            204 => ["No Content", "The server successfully processed the request but is not returning any content."],
            205 => ["Reset Content", "The server successfully processed the request but is not returning any content. The client should clear the document view."],
            206 => ["Partial Content", "The server is delivering only part of the resource due to a range header sent by the client."],
            207 => ["Multi-Status", "The message body that follows is by default an XML message and can contain a number of separate response codes, depending on how many sub-requests were made."],
            208 => ["Already Reported", "The members of a DAV binding have already been enumerated in a preceding part of the (multistatus) response, and are not being included again."],
            226 => ["IM Used", "The server has fulfilled a GET request for the resource, and the response is a representation of the result of one or more instance-manipulations applied to the current instance."],
            300 => ["Multiple Choices", "The requested resource corresponds to any one of a set of representations, each with its own specific location."],
            301 => ["Moved Permanently", "The requested resource has been assigned a new permanent URI and any future references to this resource should use one of the returned URIs."],
            302 => ["Found", "The requested resource resides temporarily under a different URI."],
            303 => ["See Other", "The response to the request can be found under a different URI and should be retrieved using a GET method on that resource."],
            304 => ["Not Modified", "Indicates that the resource has not been modified since the version specified by the request headers If-Modified-Since or If-None-Match."],
            305 => ["Use Proxy", "The requested resource must be accessed through the proxy given by the Location field."],
            306 => ["Unused", "This status code is no longer used and is not a real status code that the server sends."],
            307 => ["Temporary Redirect", "The requested resource resides temporarily under a different URI."],
            308 => ["Permanent Redirect", "The target resource has been assigned a new permanent URI and any future references to this resource out to use one of the enclosed URIs."],
            400 => ["Bad Request", "The request could not be understood or was missing required parameters."],
            401 => ["Unauthorized", "Authentication is required and has failed or has not been provided."],
            402 => ["Payment Required", "Reserved for future use."],
            403 => ["Forbidden", "The server understood the request, but it refuses to authorize it."],
            404 => ["Not Found", "The requested resource could not be found on the server."],
            405 => ["Method Not Allowed", "The method specified in the request is not allowed for the resource identified by the request URI."],
            406 => ["Not Acceptable", "The requested resource is capable of generating only content not acceptable according to the Accept headers sent in the request."],
            407 => ["Proxy Authentication Required", "The client must first authenticate itself with the proxy."],
            408 => ["Request Timeout", "The server timed out waiting for the request."],
            409 => ["Conflict", "The request could not be completed because of a conflict in the request."],
            410 => ["Gone", "The requested resource is no longer available on the server."],
            411 => ["Length Required", "The request did not specify the length of its content, which is required by the requested resource."],
            412 => ["Precondition Failed", "The server does not meet one of the preconditions specified in the request headers."],
            413 => ["Payload Too Large", "The request is larger than the server is willing or able to process."],
            414 => ["URI Too Long", "The URI provided was too long for the server to process."],
            415 => ["Unsupported Media Type", "The request entity has a media type which the server or resource does not support."],
            416 => ["Range Not Satisfiable", "The client has asked for a portion of the file (byte serving), but the server cannot supply that portion."],
            417 => ["Expectation Failed", "The server cannot meet the requirements of the Expect request-header field."],
            418 => ["I'm a teapot", "This code was defined in 1998 as one of the traditional IETF April Fools' jokes, in RFC 2324, Hyper Text Coffee Pot Control Protocol."],
            421 => ["Misdirected Request", "The request was directed at a server that is not able to produce a response (for example because of connection reuse)."],
            422 => ["Unprocessable Entity", "The request was well-formed but was unable to be followed due to semantic errors."],
            423 => ["Locked", "The resource that is being accessed is locked."],
            424 => ["Failed Dependency", "The request failed because it depended on another request and that request failed."],
            425 => ["Too Early", "Indicates that the server is unwilling to risk processing a request that might be replayed."],
            426 => ["Upgrade Required", "The client should switch to a different protocol such as TLS/1.0."],
            428 => ["Precondition Required", "The origin server requires the request to be conditional."],
            429 => ["Too Many Requests", "The user has sent too many requests in a given amount of time."],
            431 => ["Request Header Fields Too Large", "The server is unwilling to process the request because its header fields are too large."],
            451 => ["Unavailable For Legal Reasons", "A server operator has received a legal demand to deny access to a resource or to a set of resources that includes the requested resource."],
            500 => ["Internal Server Error", "A generic error message returned when an unexpected condition was encountered on the server."],
            501 => ["Not Implemented", "The server does not recognize the request method."],
            502 => ["Bad Gateway", "The server, while acting as a gateway or proxy, received an invalid response from the upstream server it accessed in attempting to fulfill the request."],
            503 => ["Service Unavailable", "The server is currently unable to handle the request due to temporary overloading or maintenance of the server."],
            504 => ["Gateway Timeout", "The server, while acting as a gateway or proxy, did not receive a timely response from the upstream server or some other auxiliary server it needed to access in order to complete the request."],
            505 => ["HTTP Version Not Supported", "The server does not support the HTTP protocol version that was used in the request."],
            506 => ["Variant Also Negotiates", "Transparent content negotiation for the request results in a circular reference."],
            507 => ["Insufficient Storage", "The server is unable to store the representation needed to complete the request."],
            508 => ["Loop Detected", "The server detected an infinite loop while processing a request."],
            510 => ["Not Extended", "Further extensions to the request are required for the server to fulfill it."],
            511 => ["Network Authentication Required", "The client needs to authenticate to gain network access."],
        ];
    }

    private function getHttpErrorInfo($errorCode) {
        $allHttpStatusCodes = $this->getAllHttpStatusCodesInfo();

        if (array_key_exists($errorCode, $allHttpStatusCodes)) {
            return $allHttpStatusCodes[$errorCode];
        } else {
            return ["Unknown Error", "Something went wrong. Please, contact administrator for more info."];
        }
    }
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  AES implementation in PHP                                                                     */
/*    (c) Chris Veness 2005-2014 www.movable-type.co.uk/scripts                                   */
/*    Right of free use is granted for all commercial or non-commercial use under CC-BY licence.  */
/*    No warranty of any form is offered.                                                         */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

Class Aes
{
    /**
     * AES Cipher function [§5.1]: encrypt 'input' with Rijndael algorithm
     *
     * @param input message as byte-array (16 bytes)
     * @param w     key schedule as 2D byte-array (Nr+1 x Nb bytes) -
     *              generated from the cipher key by keyExpansion()
     * @return      ciphertext as byte-array (16 bytes)
     */
    public static function cipher($input, $w)
    {
        $Nb = 4; // block size (in words): no of columns in state (fixed at 4 for AES)
        $Nr = count($w) / $Nb - 1; // no of rounds: 10/12/14 for 128/192/256-bit keys

        $state = array(); // initialise 4xNb byte-array 'state' with input [§3.4]
        for ($i = 0; $i < 4 * $Nb; $i++) $state[$i % 4][floor($i / 4)] = $input[$i];

        $state = self::addRoundKey($state, $w, 0, $Nb);

        for ($round = 1; $round < $Nr; $round++) { // apply Nr rounds
            $state = self::subBytes($state, $Nb);
            $state = self::shiftRows($state, $Nb);
            $state = self::mixColumns($state, $Nb);
            $state = self::addRoundKey($state, $w, $round, $Nb);
        }

        $state = self::subBytes($state, $Nb);
        $state = self::shiftRows($state, $Nb);
        $state = self::addRoundKey($state, $w, $Nr, $Nb);

        $output = array(4 * $Nb); // convert state to 1-d array before returning [§3.4]
        for ($i = 0; $i < 4 * $Nb; $i++) $output[$i] = $state[$i % 4][floor($i / 4)];
        return $output;
    }


    /**
     * Xor Round Key into state S [§5.1.4].
     */
    private static function addRoundKey($state, $w, $rnd, $Nb)
    {
        for ($r = 0; $r < 4; $r++) {
            for ($c = 0; $c < $Nb; $c++) $state[$r][$c] ^= $w[$rnd * 4 + $c][$r];
        }
        return $state;
    }

    /**
     * Apply SBox to state S [§5.1.1].
     */
    private static function subBytes($s, $Nb)
    {
        for ($r = 0; $r < 4; $r++) {
            for ($c = 0; $c < $Nb; $c++) $s[$r][$c] = self::$sBox[$s[$r][$c]];
        }
        return $s;
    }

    /**
     * Shift row r of state S left by r bytes [§5.1.2].
     */
    private static function shiftRows($s, $Nb)
    {
        $t = array(4);
        for ($r = 1; $r < 4; $r++) {
            for ($c = 0; $c < 4; $c++) $t[$c] = $s[$r][($c + $r) % $Nb]; // shift into temp copy
            for ($c = 0; $c < 4; $c++) $s[$r][$c] = $t[$c]; // and copy back
        } // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
        return $s; // see fp.gladman.plus.com/cryptography_technology/rijndael/aes.spec.311.pdf
    }

    /**
     * Combine bytes of each col of state S [§5.1.3].
     */
    private static function mixColumns($s, $Nb)
    {
        for ($c = 0; $c < 4; $c++) {
            $a = array(4); // 'a' is a copy of the current column from 's'
            $b = array(4); // 'b' is a•{02} in GF(2^8)
            for ($i = 0; $i < 4; $i++) {
                $a[$i] = $s[$i][$c];
                $b[$i] = $s[$i][$c] & 0x80 ? $s[$i][$c] << 1 ^ 0x011b : $s[$i][$c] << 1;
            }
            // a[n] ^ b[n] is a•{03} in GF(2^8)
            $s[0][$c] = $b[0] ^ $a[1] ^ $b[1] ^ $a[2] ^ $a[3]; // 2*a0 + 3*a1 + a2 + a3
            $s[1][$c] = $a[0] ^ $b[1] ^ $a[2] ^ $b[2] ^ $a[3]; // a0 * 2*a1 + 3*a2 + a3
            $s[2][$c] = $a[0] ^ $a[1] ^ $b[2] ^ $a[3] ^ $b[3]; // a0 + a1 + 2*a2 + 3*a3
            $s[3][$c] = $a[0] ^ $b[0] ^ $a[1] ^ $a[2] ^ $b[3]; // 3*a0 + a1 + a2 + 2*a3
        }
        return $s;
    }

    /**
     * Generate Key Schedule from Cipher Key [§5.2].
     *
     * Perform key expansion on cipher key to generate a key schedule.
     *
     * @param  key cipher key byte-array (16 bytes).
     * @return key schedule as 2D byte-array (Nr+1 x Nb bytes).
     */
    public static function keyExpansion($key)
    {
        $Nb = 4; // block size (in words): no of columns in state (fixed at 4 for AES)
        $Nk = count($key) / 4; // key length (in words): 4/6/8 for 128/192/256-bit keys
        $Nr = $Nk + 6; // no of rounds: 10/12/14 for 128/192/256-bit keys

        $w = array();
        $temp = array();

        for ($i = 0; $i < $Nk; $i++) {
            $r = array($key[4 * $i], $key[4 * $i + 1], $key[4 * $i + 2], $key[4 * $i + 3]);
            $w[$i] = $r;
        }

        for ($i = $Nk; $i < ($Nb * ($Nr + 1)); $i++) {
            $w[$i] = array();
            for ($t = 0; $t < 4; $t++) $temp[$t] = $w[$i - 1][$t];
            if ($i % $Nk == 0) {
                $temp = self::subWord(self::rotWord($temp));
                for ($t = 0; $t < 4; $t++) $temp[$t] ^= self::$rCon[$i / $Nk][$t];
            } else if ($Nk > 6 && $i % $Nk == 4) {
                $temp = self::subWord($temp);
            }
            for ($t = 0; $t < 4; $t++) $w[$i][$t] = $w[$i - $Nk][$t] ^ $temp[$t];
        }
        return $w;
    }

    /**
     * Apply SBox to 4-byte word w.
     */
    private static function subWord($w)
    {
        for ($i = 0; $i < 4; $i++) $w[$i] = self::$sBox[$w[$i]];
        return $w;
    }

    /**
     * Rotate 4-byte word w left by one byte.
     */
    private static function rotWord($w)
    {
        $tmp = $w[0];
        for ($i = 0; $i < 3; $i++) $w[$i] = $w[$i + 1];
        $w[3] = $tmp;
        return $w;
    }

    // sBox is pre-computed multiplicative inverse in GF(2^8) used in subBytes and keyExpansion [§5.1.1]
    private static $sBox = array(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16);

    // rCon is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [§5.2]
    private static $rCon = array(
        array(0x00, 0x00, 0x00, 0x00),
        array(0x01, 0x00, 0x00, 0x00),
        array(0x02, 0x00, 0x00, 0x00),
        array(0x04, 0x00, 0x00, 0x00),
        array(0x08, 0x00, 0x00, 0x00),
        array(0x10, 0x00, 0x00, 0x00),
        array(0x20, 0x00, 0x00, 0x00),
        array(0x40, 0x00, 0x00, 0x00),
        array(0x80, 0x00, 0x00, 0x00),
        array(0x1b, 0x00, 0x00, 0x00),
        array(0x36, 0x00, 0x00, 0x00));

}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  AES counter (CTR) mode implementation in PHP                                                  */
/*    (c) Chris Veness 2005-2014 www.movable-type.co.uk/scripts                                   */
/*    Right of free use is granted for all commercial or non-commercial use under CC-BY licence.  */
/*    No warranty of any form is offered.                                                         */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

Class AesCtr extends Aes
{

    /**
     * Encrypt a text using AES encryption in Counter mode of operation
     *  - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
     *
     * Unicode multi-byte character safe
     *
     * @param plaintext source text to be encrypted
     * @param password  the password to use to generate a key
     * @param nBits     number of bits to be used in the key (128, 192, or 256)
     * @return          encrypted text
     */
    public static function encrypt($plaintext, $password, $nBits)
    {
        $blockSize = 16; // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        if (!($nBits == 128 || $nBits == 192 || $nBits == 256)) return ''; // standard allows 128/192/256 bit keys
        // note PHP (5) gives us plaintext and password in UTF8 encoding!

        // use AES itself to encrypt password to get cipher key (using plain password as source for
        // key expansion) - gives us well encrypted key
        $nBytes = $nBits / 8; // no bytes in key
        $pwBytes = array();
        for ($i = 0; $i < $nBytes; $i++) $pwBytes[$i] = ord(substr($password, $i, 1)) & 0xff;
        $key = Aes::cipher($pwBytes, Aes::keyExpansion($pwBytes));
        $key = array_merge($key, array_slice($key, 0, $nBytes - 16)); // expand key to 16/24/32 bytes long

        // initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A §B.2): [0-1] = millisec,
        // [2-3] = random, [4-7] = seconds, giving guaranteed sub-ms uniqueness up to Feb 2106
        $counterBlock = array();
        $nonce = floor(microtime(true) * 1000); // timestamp: milliseconds since 1-Jan-1970
        $nonceMs = $nonce % 1000;
        $nonceSec = floor($nonce / 1000);
        $nonceRnd = floor(rand(0, 0xffff));

        for ($i = 0; $i < 2; $i++) $counterBlock[$i] = self::urs($nonceMs, $i * 8) & 0xff;
        for ($i = 0; $i < 2; $i++) $counterBlock[$i + 2] = self::urs($nonceRnd, $i * 8) & 0xff;
        for ($i = 0; $i < 4; $i++) $counterBlock[$i + 4] = self::urs($nonceSec, $i * 8) & 0xff;

        // and convert it to a string to go on the front of the ciphertext
        $ctrTxt = '';
        for ($i = 0; $i < 8; $i++) $ctrTxt .= chr($counterBlock[$i]);

        // generate key schedule - an expansion of the key into distinct Key Rounds for each round
        $keySchedule = Aes::keyExpansion($key);
        //print_r($keySchedule);

        $blockCount = ceil(strlen($plaintext) / $blockSize);
        $ciphertxt = array(); // ciphertext as array of strings

        for ($b = 0; $b < $blockCount; $b++) {
            // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
            // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c] = self::urs($b, $c * 8) & 0xff;
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c - 4] = self::urs($b / 0x100000000, $c * 8);

            $cipherCntr = Aes::cipher($counterBlock, $keySchedule); // -- encrypt counter block --

            // block size is reduced on final block
            $blockLength = $b < $blockCount - 1 ? $blockSize : (strlen($plaintext) - 1) % $blockSize + 1;
            $cipherByte = array();

            for ($i = 0; $i < $blockLength; $i++) { // -- xor plaintext with ciphered counter byte-by-byte --
                $cipherByte[$i] = $cipherCntr[$i] ^ ord(substr($plaintext, $b * $blockSize + $i, 1));
                $cipherByte[$i] = chr($cipherByte[$i]);
            }
            $ciphertxt[$b] = implode('', $cipherByte); // escape troublesome characters in ciphertext
        }

        // implode is more efficient than repeated string concatenation
        $ciphertext = $ctrTxt . implode('', $ciphertxt);
        $ciphertext = base64_encode($ciphertext);
        return $ciphertext;
    }


    /**
     * Decrypt a text encrypted by AES in counter mode of operation
     *
     * @param ciphertext source text to be decrypted
     * @param password   the password to use to generate a key
     * @param nBits      number of bits to be used in the key (128, 192, or 256)
     * @return           decrypted text
     */
    public static function decrypt($ciphertext, $password, $nBits)
    {
        $blockSize = 16; // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        if (!($nBits == 128 || $nBits == 192 || $nBits == 256)) return ''; // standard allows 128/192/256 bit keys
        $ciphertext = base64_decode($ciphertext);

        // use AES to encrypt password (mirroring encrypt routine)
        $nBytes = $nBits / 8; // no bytes in key
        $pwBytes = array();
        for ($i = 0; $i < $nBytes; $i++) $pwBytes[$i] = ord(substr($password, $i, 1)) & 0xff;
        $key = Aes::cipher($pwBytes, Aes::keyExpansion($pwBytes));
        $key = array_merge($key, array_slice($key, 0, $nBytes - 16)); // expand key to 16/24/32 bytes long

        // recover nonce from 1st element of ciphertext
        $counterBlock = array();
        $ctrTxt = substr($ciphertext, 0, 8);
        for ($i = 0; $i < 8; $i++) $counterBlock[$i] = ord(substr($ctrTxt, $i, 1));

        // generate key schedule
        $keySchedule = Aes::keyExpansion($key);

        // separate ciphertext into blocks (skipping past initial 8 bytes)
        $nBlocks = ceil((strlen($ciphertext) - 8) / $blockSize);
        $ct = array();
        for ($b = 0; $b < $nBlocks; $b++) $ct[$b] = substr($ciphertext, 8 + $b * $blockSize, 16);
        $ciphertext = $ct; // ciphertext is now array of block-length strings

        // plaintext will get generated block-by-block into array of block-length strings
        $plaintxt = array();

        for ($b = 0; $b < $nBlocks; $b++) {
            // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c] = self::urs($b, $c * 8) & 0xff;
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c - 4] = self::urs(($b + 1) / 0x100000000 - 1, $c * 8) & 0xff;

            $cipherCntr = Aes::cipher($counterBlock, $keySchedule); // encrypt counter block

            $plaintxtByte = array();
            for ($i = 0; $i < strlen($ciphertext[$b]); $i++) {
                // -- xor plaintext with ciphered counter byte-by-byte --
                $plaintxtByte[$i] = $cipherCntr[$i] ^ ord(substr($ciphertext[$b], $i, 1));
                $plaintxtByte[$i] = chr($plaintxtByte[$i]);

            }
            $plaintxt[$b] = implode('', $plaintxtByte);
        }

        // join array of blocks into single plaintext string
        $plaintext = implode('', $plaintxt);

        return $plaintext;
    }


    /*
     * Unsigned right shift function, since PHP has neither >>> operator nor unsigned ints
     *
     * @param a  number to be shifted (32-bit integer)
     * @param b  number of bits to shift a to the right (0..31)
     * @return   a right-shifted and zero-filled by b bits
     */
    private static function urs($a, $b)
    {
        $a &= 0xffffffff;
        $b &= 0x1f; // (bounds check)
        if ($a & 0x80000000 && $b > 0) { // if left-most bit set
            $a = ($a >> 1) & 0x7fffffff; //   right-shift one bit & clear left-most bit
            $a = $a >> ($b - 1); //   remaining right-shifts
        } else { // otherwise
            $a = ($a >> $b); //   use normal right-shift
        }
        return $a;
    }

}
?>
