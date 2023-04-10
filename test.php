<?php

require_once("signaturev4.php");

$awssig = new awssignature();

$data = "";
$method = "GET";
$host = $this->api_host;
$queryUrl = "";
$uri = "/sellers/v1/marketplaceParticipations";
$requestUrl = "https://$host$uri?$queryUrl";

$headers = $this->calculateSignature($host, $uri, $queryUrl, $requestUrl, $awssig->getAmzAccessKey(), $awssig->getAmzAccessSecret(), "us-east-1", "execute-api", $method, $data);
$json = $this->sendRequest($requestUrl, $method,  $headers, $data);
echo "json == $json";
