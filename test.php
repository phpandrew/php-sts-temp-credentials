require_once("signaturev4.php");

$awssig = new awssignature();

$awssig->setTokens("Atza|your_token_here");

$data = "";
$method = "GET";
$host = "sellingpartnerapi-na.amazon.com";
$queryUrl = "";
$uri = "/sellers/v1/marketplaceParticipations";
$requestUrl = "https://$host$uri?$queryUrl";

$headers = $awssig->calculateSignature($host, $uri, $queryUrl, $requestUrl, $awssig->getAmzAccessKey(), $awssig->getAmzAccessSecret(), "us-east-1", "execute-api", $method, $data);
$json = $awssig->sendRequest($requestUrl, $method,  $headers, $data);
print_r($json);
