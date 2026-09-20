<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Stub;

use GuzzleHttp\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Serves a scripted sequence of responses and records what was asked for.
 *
 * An entry that is a \Throwable is thrown instead of returned, which is how a
 * directory outage is staged.
 *
 * @internal
 */
final class StubHttpClient implements ClientInterface
{
    /** @var list<string> every URL requested, in order */
    public array $urls = [];

    /** @param list<ResponseInterface|\Throwable> $responses served in order, the last one repeating */
    public function __construct(
        private readonly array $responses,
    ) {}

    public static function json(string $body, int $status = 200): ResponseInterface
    {
        return new Response($status, ['Content-Type' => 'application/json'], $body);
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->urls[] = (string) $request->getUri();
        $response = $this->responses[min(\count($this->urls) - 1, \count($this->responses) - 1)];

        if ($response instanceof \Throwable) {
            throw $response;
        }

        return $response;
    }
}
