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

    public function GET_paged($callback, $path, $params = [], $page_limit = null, $max_requests = null) : void
    {
        $page_start_id = null;
        $extra_params = [];
        if (!is_numeric($page_limit)) {
            $extra_params['page_limit'] = $page_limit;
        }

        $request_count = 0;

        do {
            $data = $this->GET($path, array_merge($params, $extra_params));
            $request_count++;
            if (is_null($data)) break;

            $callback($data);

            if (!isset($data['pagination'])) break;
            if (!is_null($max_requests) && $request_count >= $max_requests) break;

            $extra_params['page_start_id'] = $data['pagination']['next_page_start_id'];
        } while(1);
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
