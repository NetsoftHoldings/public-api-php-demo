<?php

namespace Hubstaff;

use Psr\Http\Message\ResponseInterface;
use Throwable;

class HTTPBaseException extends \RuntimeException
{
    /** @var ResponseInterface */
    private $response;

    function __construct($message, ResponseInterface $response, Throwable $previous = null)
    {
        $this->response = $response;
        parent::__construct($message, $response->getStatusCode(), $previous);
    }

    public function getResponse(): ResponseInterface
    {
        return $this->response;
    }
}