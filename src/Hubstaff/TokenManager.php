<?php


namespace Hubstaff;

use Facile\OpenIDClient\Client\ClientBuilder;
use Facile\OpenIDClient\Client\ClientInterface;
use Facile\OpenIDClient\Client\Metadata\ClientMetadata;
use Facile\OpenIDClient\Issuer\IssuerBuilder;
use Facile\OpenIDClient\Issuer\IssuerInterface;
use Facile\OpenIDClient\Issuer\Metadata\Provider\MetadataProviderBuilder;
use Facile\JoseVerifier\JWK\JwksProviderBuilder;
use Facile\OpenIDClient\Service\AuthorizationService;
use Facile\OpenIDClient\Token\TokenSetFactory;
use Facile\OpenIDClient\Token\TokenSetInterface;
use Jose\Component\Core\JWKSet;
use Jose\Easy\Load;

class TokenManager
{
    const ACCESS_TOKEN_EXPIRATION_FUZZ = 30;

    /** @var ClientInterface */
    private $client;

    /** @var IssuerInterface */
    private $issuer;

    /** @var StateManager */
    private $state;

    /** @var TokenSetInterface */
    private $token;

    function __construct(StateManager $state)
    {
        $this->state = $state;

        $this->setupCache();

        $this->loadIssuer();

        $this->loadToken();

        $this->loadClient();

        $this->checkToken();
    }

    private function setupCache()
    {
        $cache_namespace = str_replace(
            array('https://', 'http://', '/'),
            array('', '', ''),
            $this->state->config['issuer_url']
        );

        $this->state->setupCache($cache_namespace);
    }

    private function loadIssuer()
    {
        $metadataProviderBuilder = (new MetadataProviderBuilder())
            ->setCache($this->state->cache())
            ->setCacheTtl(86400 * 7); // Cache metadata for 7 days

        $jwksProviderBuilder = (new JwksProviderBuilder())
            ->setCache($this->state->cache())
            ->setCacheTtl(86400); // Cache JWKS for 1 day

        $issuerBuilder = (new IssuerBuilder())
            ->setMetadataProviderBuilder($metadataProviderBuilder)
            ->setJwksProviderBuilder($jwksProviderBuilder);

        $this->issuer = $issuerBuilder->build($this->state->config['issuer_url']);
    }

    private function loadClient()
    {
        $clientMetadata = ClientMetadata::fromArray([
            'token_endpoint_auth_method' => 'client_secret_basic',
            // These are only set as this OpenID library requires a client_id/secret
            'client_id' => 'PAT',
            'client_secret' => 'PAT',
        ]);

        $this->client = (new ClientBuilder())
            ->setIssuer($this->issuer)
            ->setClientMetadata($clientMetadata)
            ->build();
    }

    private function loadToken()
    {
        $tokenFactory = new TokenSetFactory();
        $this->token = $tokenFactory->fromArray($this->state->config['token']);
    }

    private function getTokenExp($token)
    {
        $jwks = $this->issuer->getJwksProvider()->getJwks();
        $jwkset = JWKSet::createFromKeyData($jwks);
        $jws = Load::jws($token)
            ->keyset($jwkset)
            ->run();
        return $jws->claims->exp();
    }

    function checkToken()
    {
        $expired = empty($this->token->getAccessToken());
        if (!$expired) {
            $expired = $this->getTokenExp($this->token->getAccessToken()) < (time() + self::ACCESS_TOKEN_EXPIRATION_FUZZ);
        }
        if ($expired) {
            $authorizationService = (new AuthorizationService());
            $this->token = $authorizationService->refresh($this->client, $this->state->config['token']['refresh_token']);
            $this->state->config['token'] = array(
                'access_token' => $this->token->getAccessToken(),
                'refresh_token' => $this->token->getRefreshToken(),
                'expires_at' => $this->getTokenExp($this->token->getAccessToken()),
            );
            $this->state->save();
        }
    }

    function token(): TokenSetInterface
    {
        $this->checkToken();

        return $this->token;
    }

    function APIBaseURL()
    {
        return $this->state->config['api_base_url'];
    }

}