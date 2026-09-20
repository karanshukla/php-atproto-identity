<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Resolution;

use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Resolution\DidDocumentUrl;
use KaranShukla\PhpAtprotoIdentity\Resolution\HttpDidDocumentResolver;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class DidDocumentUrlTest extends TestCase
{
    public function testAsksThePlcDirectoryForADidPlc(): void
    {
        self::assertSame(
            'https://plc.directory/did:plc:requester',
            DidDocumentUrl::for('did:plc:requester', HttpDidDocumentResolver::PLC_DIRECTORY),
        );
    }

    public function testDoesNotDoubleTheSlashOnADirectoryThatEndsInOne(): void
    {
        self::assertSame(
            'https://plc.example.test/did:plc:requester',
            DidDocumentUrl::for('did:plc:requester', 'https://plc.example.test/'),
        );
    }

    public function testAsksTheDomainItselfForADidWeb(): void
    {
        self::assertSame(
            'https://feed.test/.well-known/did.json',
            DidDocumentUrl::for('did:web:feed.test', HttpDidDocumentResolver::PLC_DIRECTORY),
        );
    }

    public function testDecodesAPercentEncodedDidWebHost(): void
    {
        // The port separator is the one character a did:web host has to
        // encode, because a bare colon would read as a path.
        self::assertSame(
            'https://feed.test:3000/.well-known/did.json',
            DidDocumentUrl::for('did:web:feed.test%3A3000', HttpDidDocumentResolver::PLC_DIRECTORY),
        );
    }

    /** An IDN did:web is punycode by the time it is an identifier. */
    public function testAcceptsAPunycodeHost(): void
    {
        self::assertSame(
            'https://xn--e1afmkfd.xn--p1ai/.well-known/did.json',
            DidDocumentUrl::for('did:web:xn--e1afmkfd.xn--p1ai', HttpDidDocumentResolver::PLC_DIRECTORY),
        );
    }

    /**
     * A DID arrives from outside -- a token's issuer field, a record's
     * subject -- and every character of it ends up in a URL this process
     * fetches, so an identifier that is not a plain hostname is refused
     * before it can bend the URL somewhere else.
     *
     * @param non-empty-string $did
     */
    #[DataProvider('provideRefusesAnIdentifierThatWouldBendTheUrlCases')]
    public function testRefusesAnIdentifierThatWouldBendTheUrl(string $did): void
    {
        $this->expectException(IdentityException::class);

        DidDocumentUrl::for($did, HttpDidDocumentResolver::PLC_DIRECTORY);
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function provideRefusesAnIdentifierThatWouldBendTheUrlCases(): iterable
    {
        // https://trusted.test@evil.test/... reads as trusted.test and is
        // fetched from evil.test. The rest are the same trick aimed at the
        // path, the query and the fragment.
        yield 'userinfo' => ['did:web:trusted.test%40evil.test'];
        yield 'path' => ['did:web:feed.test%2F..%2Fadmin'];
        yield 'query' => ['did:web:feed.test%3Fredirect%3Devil.test'];
        yield 'fragment' => ['did:web:feed.test%23'];
        yield 'a second host' => ['did:web:feed.test%20evil.test'];
        yield 'an empty host' => ['did:web:'];
        yield 'a hostname that is not one' => ['did:web:-feed.test'];
        yield 'an empty label' => ['did:web:feed..test'];
        yield 'a plc identifier with a path in it' => ['did:plc:requester/../../admin'];
        yield 'a plc identifier with a host in it' => ['did:plc:requester%40evil.test'];

        // Nothing below would bend the URL. They are refused because of where
        // the URL points: a did:web is a domain someone had to register, and
        // none of these is one. Egress is still the HTTP client's to bound,
        // but these are the shapes that get there by accident.
        yield 'loopback by name' => ['did:web:localhost'];
        yield 'loopback by address' => ['did:web:127.0.0.1'];
        yield 'the cloud metadata address' => ['did:web:169.254.169.254'];
        yield 'an address written in hex' => ['did:web:0x7f.0.0.1'];
        yield 'an address written as one integer' => ['did:web:2130706433'];
        yield 'a container or service name' => ['did:web:redis'];
        yield 'an internal single-label host with a port' => ['did:web:redis%3A6379'];
        yield 'a numeric tld' => ['did:web:feed.123'];
        yield 'an identifier longer than any hostname' => ['did:web:' . str_repeat('a', 300) . '.test'];
        yield 'a plc identifier longer than any of them' => ['did:plc:' . str_repeat('a', 300)];
    }

    public function testRejectsADidWebWithAPath(): void
    {
        $this->expectException(IdentityException::class);

        DidDocumentUrl::for('did:web:feed.test:user:alice', HttpDidDocumentResolver::PLC_DIRECTORY);
    }

    public function testRejectsADidMethodWithNoUrlRule(): void
    {
        $this->expectException(IdentityException::class);

        DidDocumentUrl::for('did:example:nope', HttpDidDocumentResolver::PLC_DIRECTORY);
    }
}
