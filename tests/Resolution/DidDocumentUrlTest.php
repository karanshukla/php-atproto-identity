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

    public function testDecodesAPercentEncodedPortSeparator(): void
    {
        self::assertSame(
            'https://feed.test:3000/.well-known/did.json',
            DidDocumentUrl::for('did:web:feed.test%3A3000', HttpDidDocumentResolver::PLC_DIRECTORY),
        );
    }

    public function testAcceptsAPunycodeHost(): void
    {
        self::assertSame(
            'https://xn--e1afmkfd.xn--p1ai/.well-known/did.json',
            DidDocumentUrl::for('did:web:xn--e1afmkfd.xn--p1ai', HttpDidDocumentResolver::PLC_DIRECTORY),
        );
    }

    /**
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
        yield 'userinfo, which would read as one host and fetch another' => ['did:web:trusted.test%40evil.test'];

        yield 'path' => ['did:web:feed.test%2F..%2Fadmin'];

        yield 'query' => ['did:web:feed.test%3Fredirect%3Devil.test'];

        yield 'fragment' => ['did:web:feed.test%23'];

        yield 'a second host' => ['did:web:feed.test%20evil.test'];

        yield 'an empty host' => ['did:web:'];

        yield 'a hostname that is not one' => ['did:web:-feed.test'];

        yield 'an empty label' => ['did:web:feed..test'];

        yield 'a plc identifier with a path in it' => ['did:plc:requester/../../admin'];

        yield 'a plc identifier with a host in it' => ['did:plc:requester%40evil.test'];
    }

    /**
     * @param non-empty-string $did
     */
    #[DataProvider('provideRefusesAnIdentifierLongerThanAnyRealOneCases')]
    public function testRefusesAnIdentifierLongerThanAnyRealOne(string $did): void
    {
        $this->expectException(IdentityException::class);

        DidDocumentUrl::for($did, HttpDidDocumentResolver::PLC_DIRECTORY);
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function provideRefusesAnIdentifierLongerThanAnyRealOneCases(): iterable
    {
        yield 'longer than any hostname' => ['did:web:' . str_repeat('a', 300) . '.test'];

        yield 'longer than any plc identifier' => ['did:plc:' . str_repeat('a', 300)];
    }

    /**
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesAHostThatIsNotAPublicDomain()
     */
    public function testLeavesTheQuestionOfAPrivateHostToTheResolver(): void
    {
        self::assertSame(
            'https://localhost:3000/.well-known/did.json',
            DidDocumentUrl::for('did:web:localhost%3A3000', HttpDidDocumentResolver::PLC_DIRECTORY),
        );
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
