<?php


namespace Hubstaff;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Http\Message\Authentication\Bearer;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;

class APIManager
{
    /** @var TokenManager */
    private $token;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    /** @var UriFactoryInterface */
    private $uriFactory;

    /** @var StreamFactoryInterface */
    private $streamFactory;

    /** @var ClientInterface */
    private $httpClient;

    function __construct(TokenManager $manager)
    {
        $this->token = $manager;

        $this->requestFactory = Psr17FactoryDiscovery::findRequestFactory();

        $this->uriFactory = Psr17FactoryDiscovery::findUriFactory();

        $this->streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        $this->httpClient = Psr18ClientDiscovery::find();
    }

    private function makeRequest(RequestInterface $request)
    {
        $bearer = new Bearer($this->token->token()->getAccessToken());

        $request = $bearer->authenticate($request);

        $response = $this->httpClient->sendRequest($request);

        return json_decode((string)$response->getBody(), true);
    }

    public function GET($path, $params = [])
    {
        $query = http_build_query($params);

        $uri = $this->uriFactory->createUri($this->token->APIBaseURL() . $path);
        $uri = $uri->withQuery($query);

        $request = $this->requestFactory->createRequest('GET', $uri);

        return $this->makeRequest($request);
    }

    public function POST($path, $params = [])
    {
        $uri = $this->uriFactory->createUri($this->token->APIBaseURL() . $path);

        $body = $this->streamFactory->createStream(json_encode($params));

        $request = $this->requestFactory->createRequest('POST', $uri)
            ->withHeader('Content-Type', 'application/json')
        ->withBody($body);

        return $this->makeRequest($request);
    }
}