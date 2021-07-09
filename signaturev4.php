<?php

/**
 * Generate temporary session token and credentials with Amazon sts.amazonaws.com 
 * This script generates temporary credentials with SignatureV4.
 */

function calcualteAwsSignatureAndReturnHeaders($host, $uri, $queryUrl, $requestUrl, $accessKey, $secretKey, $region, $service, $httpRequestMethod, $data, $debug = TRUE) {

  $useragent 			= "php-sts-temp-credentials";
  $terminationString 	= 'aws4_request';
  $algorithm    		= 'AWS4-HMAC-SHA256';
  $phpAlgorithm     	= 'sha256';
  $canonicalURI   		= $uri;
  $canonicalQueryString = http_build_query($queryUrl);
  $signedHeaders 		= "host;x-amz-date";

  $currentDateTime = new DateTime('UTC');
  $reqDate = $currentDateTime->format('Ymd');
  $reqDateTime = $currentDateTime->format('Ymd\THis\Z');

  // Create signing key
  $kSecret = $secretKey;
  $kDate = hash_hmac($phpAlgorithm, $reqDate, 'AWS4'.$kSecret, true);
  $kRegion = hash_hmac($phpAlgorithm, $region, $kDate, true);
  $kService = hash_hmac($phpAlgorithm, $service, $kRegion, true);
  $kSigning = hash_hmac($phpAlgorithm, $terminationString, $kService, true);

  // Create canonical headers
  $canonicalHeaders = array();
  $canonicalHeaders[] = 'host:' . $host;
  $canonicalHeaders[] = 'x-amz-date:' . $reqDateTime;
  $canonicalHeadersStr = implode("\n", $canonicalHeaders);

  // Create request payload
  $requestHasedPayload = hash($phpAlgorithm, $data);

  // Create canonical request
  $canonicalRequest = array();
  $canonicalRequest[] = $httpRequestMethod;
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
  $signature = hash_hmac($phpAlgorithm, utf8_encode($stringToSignStr), $kSigning); 

  // Create authorization header
  $authorizationHeader = array();
  $authorizationHeader[] = 'Credential=' . $accessKey . '/' . $credentialScopeStr;
  $authorizationHeader[] = 'SignedHeaders=' . $signedHeaders;
  $authorizationHeader[] = 'Signature=' . ($signature);
  $authorizationHeaderStr = $algorithm . ' ' . implode(', ', $authorizationHeader);

  // Request headers
  $headers = array();
  $headers[] = 'Authorization:'.$authorizationHeaderStr;
  $headers[] = 'host:' . $host;
  $headers[] = "user-agent:$useragent";
  $headers[] = 'x-amz-date:' . $reqDateTime;

  $headers[] = 'content-type:application/x-www-form-urlencoded; charset=utf-8';
  $headers[] = 'Accept: application/json';

  return $headers;
}// End calcualteAwsSignatureAndReturnHeaders

function callToAPI($requestUrl, $httpRequestMethod, $headers, $data, $debug=TRUE)
{
  // Execute the call
  $curl = curl_init();
  curl_setopt_array($curl, array(
    CURLOPT_URL => $requestUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_POST => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_CUSTOMREQUEST => $httpRequestMethod,
    //CURLOPT_POSTFIELDS => $data,
    CURLOPT_VERBOSE => 0,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_SSL_VERIFYPEER => 1,
    CURLOPT_HEADER => false,
    CURLINFO_HEADER_OUT=>true,
    CURLOPT_HTTPHEADER => $headers,
  ));

  $response = curl_exec($curl);
  $err = curl_error($curl);
  $responseCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);

  if($debug){
    $headers = curl_getinfo($curl, CURLINFO_HEADER_OUT);
    echo "<h5>Request</h5>";
    echo "<pre>";
    echo $headers;
    echo "</pre>";
  }

  curl_close($curl);
  return json_decode($response, true);
  
}// End callToAPI

$data               = "";
$httpRequestMethod  = "GET";
$host               = "sts.amazonaws.com";
$accessKey          = "Your_LWA_Access_Key";
$secretKey          = "Your_LWA_Access_Secret";
$region             = "us-east-1";
$service            = "sts";
$queryUrl 			= array("Action" => "AssumeRole",
                            "DurationSeconds" => "3600",
                            "RoleArn" => "arn:aws:iam::1234567890:role/YourRole",
                            "RoleSessionName"=> "php-generatetoken",
                            "Version" => "2011-06-15");
$uri                = "/";
$requestUrl         = "https://$host$uri?".http_build_query($queryUrl);

$headers = calcualteAwsSignatureAndReturnHeaders($host, $uri, $queryUrl, $requestUrl, $accessKey, $secretKey, $region, $service, $httpRequestMethod, $data, false);

$cred = callToAPI($requestUrl, $httpRequestMethod,  $headers, $data, false);

$AccessKeyId = $cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['AccessKeyId'];
$SecretAccessKey = $cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['SecretAccessKey'];
$Expiration = (int)$cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['Expiration'];
$SessionToken = $cred['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['SessionToken'];
