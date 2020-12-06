<?php
require_once 'vendor/autoload.php';

use Facile\OpenIDClient\Client\ClientBuilder;
use Facile\OpenIDClient\Client\Metadata\ClientMetadata;
use Facile\OpenIDClient\Issuer\IssuerBuilder;
use Facile\OpenIDClient\Issuer\Metadata\Provider\MetadataProviderBuilder;
use Facile\OpenIDClient\Service\AuthorizationService;
use Facile\JoseVerifier\JWK\JwksProviderBuilder;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

const DEFAULT_ISSUER_URL = 'https://account.hubstaff.com';
const DEFAULT_API_BASE_URL = 'https://api.hubstaff.com/';
const ACCESS_TOKEN_EXPIRATION_FUZZ = 30;

function loadState()
{
    $configData = file_get_contents('configState.json');
    return json_decode($configData, true);
}

function saveState($config)
{
    file_put_contents('configState.json', json_encode($config, JSON_PRETTY_PRINT));
}

function checkToken(&$client, &$config)
{
    if (empty($config['token']['access_token']) || $config['token']['expires_at'] < (time() + ACCESS_TOKEN_EXPIRATION_FUZZ)) {
        $authorizationService = (new AuthorizationService());
        $token = $authorizationService->refresh($client, $config['token']['refresh_token']);
        $config['token'] = array(
            'access_token' => $token->getAccessToken(),
            'refresh_token' => $token->getRefreshToken(),
            'expires_at' => $token->getExpiresIn() + time(),
        );
        saveState($config);
    }
}

$config = loadState();

if (empty($config['issuer_url'])) {
    $config['issuer_url'] = DEFAULT_ISSUER_URL;
}
if (empty($config['api_base_url'])) {
    $config['api_base_url'] = DEFAULT_API_BASE_URL;
}
saveState($config);

$cache_namespace = str_replace(array('https://', 'http://', '/'), array('', '', ''), $config['issuer_url']);

$scache = new FilesystemAdapter($cache_namespace, 0, __DIR__ . DIRECTORY_SEPARATOR . 'cache');
$cache = new Psr16Cache($scache);

$metadataProviderBuilder = (new MetadataProviderBuilder())
    ->setCache($cache)
    ->setCacheTtl(86400 * 7); // Cache metadata for 7 days

$jwksProviderBuilder = (new JwksProviderBuilder())
    ->setCache($cache)
    ->setCacheTtl(86400); // Cache JWKS for 1 day

$issuerBuilder = (new IssuerBuilder())
    ->setMetadataProviderBuilder($metadataProviderBuilder)
    ->setJwksProviderBuilder($jwksProviderBuilder);

$issuer = $issuerBuilder->build($config['issuer_url']);

$clientMetadata = ClientMetadata::fromArray([
    'client_id' => 'PAT',
    'client_secret' => 'PAT',
    'token_endpoint_auth_method' => 'client_secret_basic',
]);

$client = (new ClientBuilder())
    ->setIssuer($issuer)
    ->setClientMetadata($clientMetadata)
    ->build();

checkToken($client, $config);

$requestFactory = Psr17FactoryDiscovery::findRequestFactory();
$request = $requestFactory->createRequest('GET', $config['api_base_url'] . 'v2/users/me')
    ->withHeader('Authorization', 'Bearer ' . $config['token']['access_token']);

$httpClient = Psr18ClientDiscovery::find();
$response = $httpClient->sendRequest($request);

$body = json_decode((string)$response->getBody(), true);
var_dump($body);