<?php

/**
 * Authorize Login with Amazon
 *
 * Documentation:
 * @see  https://developer.amazon.com/docs/login-with-amazon/authorization-code-grant.html
 *
 */

include_once(dirname(__FILE__)."/config.php");

class awssignature {

    public $Access_Token;
    public $Amz_SessionToken;
    public $Amz_AccessKeyId;
    public $Amz_SecretAccessKey;
    public $Amz_CredentialsExpire;

    public $ratelimit;

    /**
     * On load, check if refresh token is required.
     *
     * @example
     */
    function __construct() {
        global $conn, $database;

        $this->Amz_AccessKeyId = "";
        $this->Amz_SecretAccessKey = "";
        $this->Amz_SessionToken = "";
        $this->Amz_CredentialsExpire = "";

        $this->updateCredentials();
    }
    public function getAmzAccessKey() {
        return $this->Amz_AccessKeyId;
    }
    public function getAmzAccessSecret() {
        return $this->Amz_SecretAccessKey;
    }
    public function setTokens($_Access_Token) {
        $this->Access_Token = $_Access_Token;
    }
    public function createUserAgent() {
        return "PHP-sts SPAPI (Language=PHP 7.3.23; Platform=Centos 6)";
    }
    /**
     * Update Amazon Session Token. Must be refreshed regularly.
     *
     * @return  [type]
     *
     * @example
     */
    public function updateCredentials() {
        global $conn, $database;

        //update credentials if within 16 minutes.
        if((time()+1000) >= $this->Amz_CredentialsExpire) {
            $data       = "";
            $method     = "GET";
            $host       = "sts.amazonaws.com";
            $accessKey  = LOGIN_CLIENTID;
            $secretKey  = LOGIN_CLIENTSECRET;
            $roleArn    = ROLE_ARN;
            $region     = "us-east-1";
            $service    = "sts";
            $queryUrl   = array("Action" => "AssumeRole",
                                "DurationSeconds" => "3600",
                                "RoleArn" => "$roleArn",
                                "RoleSessionName"=> "php-generatetoken",
                                "Version" => "2011-06-15");
            $uri        = "/";
            $requestUrl = "https://$host$uri?".http_build_query($queryUrl);

            $headers = $this->calculateSignature($host, $uri, http_build_query($queryUrl), $requestUrl, $accessKey, $secretKey, $region, $service, $method, $data, false, true);

            $array = $this->sendRequest($requestUrl, $method,  $headers, $data);
            $cred = json_decode($array['response'], true);

            if(isset($cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['AccessKeyId'])) {
                $AccessKeyId = $cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['AccessKeyId'];
                $SecretAccessKey = $cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['SecretAccessKey'];
                $Expiration = (int)$cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['Expiration'];
                $SessionToken = $cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['SessionToken'];

                //update credentials
                $this->Amz_AccessKeyId = $AccessKeyId;
                $this->Amz_SecretAccessKey = $SecretAccessKey;
                $this->Amz_SessionToken = $SessionToken;
                $this->Amz_CredentialsExpire = $Expiration;
            }
        }
    }
    /**
     * Calculate Amazon signature for making calls.
     *
     * @param   [type]  $host
     * @param   [type]  $uri
     * @param   [type]  $queryUrl
     * @param   [type]  $requestUrl
     * @param   [type]  $accessKey
     * @param   [type]  $secretKey
     * @param   [type]  $region
     * @param   [type]  $service
     * @param   [type]  $method
     * @param   [type]  $data
     * @param   boolean $debug
     * @param   boolean $awscred //toggle for renewing AWS LWA (true), or Amazon Sp-API (false)
     *
     * @return  [type]
     *
     * @example
     */
    public function calculateSignature($host, $uri, $queryUrl, $requestUrl, $accessKey, $secretKey, $region, $service, $method, $data, $debug = false, $awscred=false) {
        $useragent              = ($awscred == false ? $this->createUserAgent() : "php-sts-temp-credentials");
        $terminationString      = 'aws4_request';
        $algorithm              = 'AWS4-HMAC-SHA256';
        $phpAlgorithm           = 'sha256';
        $canonicalURI           = $uri;
        $canonicalQueryString   = $queryUrl;
        //$signedHeaders    = 'content-type;host;x-amz-date';
        if($awscred == false) {
            $signedHeaders = "host;user-agent;x-amz-access-token;x-amz-date;x-amz-security-token";
        } else {
            $signedHeaders = "host;x-amz-date";
        }

        $currentDateTime = new DateTime('UTC');
        $reqDate = $currentDateTime->format('Ymd');
        $reqDateTime = $currentDateTime->format('Ymd\THis\Z');

        // Create signing key
        $kSecret = $secretKey;
        $kDate = hash_hmac($phpAlgorithm, $reqDate, 'AWS4' . $kSecret, true);
        $kRegion = hash_hmac($phpAlgorithm, $region, $kDate, true);
        $kService = hash_hmac($phpAlgorithm, $service, $kRegion, true);
        $kSigning = hash_hmac($phpAlgorithm, $terminationString, $kService, true);

        // Create canonical headers
        $canonicalHeaders = array();
        $canonicalHeaders[] = 'host:' . $host;
        if($awscred == false) {
            $canonicalHeaders[] = "user-agent:$useragent";
            $canonicalHeaders[] = 'x-amz-access-token:' . $this->Access_Token;
            $canonicalHeaders[] = 'x-amz-date:' . $reqDateTime;
            $canonicalHeaders[] = 'x-amz-security-token:' . $this->Amz_SessionToken;
        } else {
            $canonicalHeaders[] = 'x-amz-date:' . $reqDateTime;
        }
        $canonicalHeadersStr = implode("\n", $canonicalHeaders);

        // Create request payload
        $requestHasedPayload = hash($phpAlgorithm, $data);

        // Create canonical request
        $canonicalRequest = array();
        $canonicalRequest[] = $method;
        $canonicalRequest[] = $canonicalURI;
        $canonicalRequest[] = $canonicalQueryString;
        $canonicalRequest[] = $canonicalHeadersStr . "\n";
        $canonicalRequest[] = $signedHeaders;
        $canonicalRequest[] = $requestHasedPayload;
        $requestCanonicalRequest = implode("\n", $canonicalRequest);
        $requestHasedCanonicalRequest = hash($phpAlgorithm, utf8_encode($requestCanonicalRequest));
        if($debug){
            echo "<h5>Canonical to string</h5>";
            echo "<pre>";
            echo $requestCanonicalRequest;
            echo "</pre>";
        }

        // Create scope
        $credentialScope = array();
        $credentialScope[] = $reqDate;
        $credentialScope[] = $region;
        $credentialScope[] = $service;
        $credentialScope[] = $terminationString;
        $credentialScopeStr = implode('/', $credentialScope);

        // Create string to signing
        $stringToSign = array();
        $stringToSign[] = $algorithm;
        $stringToSign[] = $reqDateTime;
        $stringToSign[] = $credentialScopeStr;
        $stringToSign[] = $requestHasedCanonicalRequest;
        $stringToSignStr = implode("\n", $stringToSign);
        if($debug){
            echo "<h5>String to Sign</h5>";
            echo "<pre>";
            echo $stringToSignStr;
            echo "</pre>";
        }

        // Create signature
        $signature = hash_hmac($phpAlgorithm, $stringToSignStr, $kSigning);

        // Create authorization header
        $authorizationHeader = array();
        $authorizationHeader[] = 'Credential=' . $accessKey . '/' . $credentialScopeStr;
        $authorizationHeader[] = 'SignedHeaders=' . $signedHeaders;
        $authorizationHeader[] = 'Signature=' . ($signature);
        $authorizationHeaderStr = $algorithm . ' ' . implode(', ', $authorizationHeader);


        // Request headers
        $headers = array();
        $headers[] = 'Authorization: '.$authorizationHeaderStr;
        $headers[] = 'host: ' . $host;
        $headers[] = "user-agent: $useragent";
        if($awscred == false) {
            $headers[] = 'x-amz-access-token: ' . $this->Access_Token;
            $headers[] = 'x-amz-date: ' . $reqDateTime;
            $headers[] = 'x-amz-security-token: '.$this->Amz_SessionToken;

            $headers[] = 'Accept: application/json';
            $headers[] = 'content-length: '.strlen($data);
            $headers[] = 'content-type: application/json';
        } else {
            $headers[] = 'x-amz-date:' . $reqDateTime;
            $headers[] = 'Content-length: '.strlen($data);
            $headers[] = 'content-type:application/x-www-form-urlencoded; charset=utf-8';
            $headers[] = 'Accept: application/json';
        }
        return $headers;
    }

    /**
     * Send request to Amazon server.
     *
     * @param   [type]  $requestUrl
     * @param   [type]  $method
     * @param   [type]  $headers
     * @param   [type]  $data
     * @param   boolean $debug
     *
     * @return  [type]
     *
     * @example
     */
    public function sendRequest(string $url, $method="POST", array $headers=array(), string $data_string=null, bool $debug=false) {
        // Execute the call
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "$url");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); 
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_POST, 1); //post if api requires
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method)); 
        if($data_string != null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string); //post field if not null
        }
        curl_setopt($ch, CURLOPT_VERBOSE, false);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0); 
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1); 
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2); 
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1); 
        curl_setopt($ch, CURLOPT_TIMEOUT, 60); //timeout in seconds
        curl_setopt($ch, CURLOPT_HEADER, false);
        //curl_setopt($ch, CURLOPT_ENCODING , "gzip");
        curl_setopt($ch, CURLOPT_HEADER, 1);
        //curl_setopt($ch, CURLINFO_HEADER_OUT, $debug); //true/false
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $result = curl_exec($ch);

        $response = curl_exec($ch);
        $err = curl_error($ch);
        $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        // Then, after your curl_exec call:
		$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
		$headersOut = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersOutArray = $this->headersToArray($headersOut);
        
        $this->ratelimit = (isset($headersOutArray['x-amzn-RateLimit-Limit']) ? $headersOutArray['x-amzn-RateLimit-Limit'] : 0);

        if($debug) {
            //$headersOut = curl_getinfo($ch, CURLINFO_HEADER_OUT);
            print_r($headersOutArray);
            echo "Rate Limit: {$this->ratelimit}";
            echo "<h5>Request</h5>";
            echo "<pre>";
            echo $headersOut;
            echo "</pre>";
        }

        curl_close($ch);

        if ($err) {
            if($debug) {
                echo "<h5>Error:" . $responseCode . "</h5>";
                echo "<pre>";
                echo $err;
                echo "</pre>";
            }
            return array(
                "responseCode" => $responseCode,
                "response" => $body,
                "error" => $err
            );
        } else {
            if($debug) {
                echo "<h5>Response:" . $responseCode . "</h5>";
                echo "<pre>";
                echo $body;
                //print_r($response);
                echo "</pre>";
            }
        }
       
        return array(
            "responseCode" => $responseCode,
            "response" => $body,
            "error" => $err
        );
    }
    /**
     * Return rate limit
     *
     * @return  [type]
     *
     * @example
     */
    public function getRateLimit() {
    	return $this->ratelimit;
    }

    /**
     * Convert headers to php array
     *
     * @param   [type] $str
     *
     * @return  [type]
     *
     * @example
     */
    function headersToArray( $str ) {
	    $headers = array();
	    $headersTmpArray = explode( "\r\n" , $str );
	    for ( $i = 0 ; $i < count( $headersTmpArray ) ; ++$i )
	    {
	        // we dont care about the two \r\n lines at the end of the headers
	        if ( strlen( $headersTmpArray[$i] ) > 0 )
	        {
	            // the headers start with HTTP status codes, which do not contain a colon so we can filter them out too
	            if ( strpos( $headersTmpArray[$i] , ":" ) )
	            {
	                $headerName = substr( $headersTmpArray[$i] , 0 , strpos( $headersTmpArray[$i] , ":" ) );
	                $headerValue = substr( $headersTmpArray[$i] , strpos( $headersTmpArray[$i] , ":" )+1 );
	                $headers[$headerName] = $headerValue;
	            }
	        }
	    }
	    return $headers;
	}
}
