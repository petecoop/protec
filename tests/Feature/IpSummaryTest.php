<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Schema;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Tests\Fixtures\CustomBlock;

it('returns an empty summary without creating records for an unknown IP', function () {
    expect(Protec::ip('203.0.113.1')->toArray())->toBe([
        'ip_address' => '203.0.113.1',
        'is_blocked' => false,
        'is_permanently_blocked' => false,
        'blocked_until' => null,
        'total_blocks' => 0,
        'active_blocks' => 0,
        'latest_block' => null,
    ]);
    $this->assertDatabaseCount('ip_blocks', 0);
});

it('summarizes retained history and the longest active block for only the requested IP', function () {
    $this->freezeSecond();
    Protec::block('203.0.113.1', for: 1);
    $this->travel(1)->seconds();
    $longest = Protec::block('203.0.113.1', for: '2d');
    $latest = Protec::block('203.0.113.1', for: '1d', reason: 'review', context: ['ticket' => 1]);
    Protec::block('203.0.113.2');

    $summary = Protec::ip('203.0.113.1');

    expect($summary->ipAddress)
        ->toBe('203.0.113.1')
        ->and($summary->isBlocked)
        ->toBeTrue()
        ->and($summary->isPermanentlyBlocked)
        ->toBeFalse()
        ->and($summary->blockedUntil->equalTo($longest->expires_at))
        ->toBeTrue()
        ->and($summary->totalBlocks)
        ->toBe(3)
        ->and($summary->activeBlocks)
        ->toBe(2)
        ->and($summary->latestBlock->is($latest))
        ->toBeTrue();

    $json = json_decode(json_encode($summary, JSON_THROW_ON_ERROR), associative: true, flags: JSON_THROW_ON_ERROR);
    expect($json)
        ->toBe($summary->toArray())
        ->and($json['blocked_until'])
        ->toBe($longest->expires_at->toISOString())
        ->and($json['latest_block']['context'])
        ->toBe(['ticket' => 1]);
});

it('reports a permanent block even when the newest block is temporary', function () {
    Protec::block('203.0.113.1');
    $latest = Protec::block('203.0.113.1', for: '1d');

    $summary = Protec::ip('203.0.113.1');

    expect($summary->isBlocked)
        ->toBeTrue()
        ->and($summary->isPermanentlyBlocked)
        ->toBeTrue()
        ->and($summary->blockedUntil)
        ->toBeNull()
        ->and($summary->activeBlocks)
        ->toBe(2)
        ->and($summary->latestBlock->is($latest))
        ->toBeTrue();
});

it('excludes an expired block from current status at the exact expiration', function () {
    $this->freezeSecond();
    $block = Protec::block('203.0.113.1', for: 60);
    $this->travel(60)->seconds();

    $summary = Protec::ip('203.0.113.1');

    expect($summary->isBlocked)
        ->toBeFalse()
        ->and($summary->isPermanentlyBlocked)
        ->toBeFalse()
        ->and($summary->blockedUntil)
        ->toBeNull()
        ->and($summary->activeBlocks)
        ->toBe(0)
        ->and($summary->totalBlocks)
        ->toBe(1)
        ->and($summary->latestBlock->is($block))
        ->toBeTrue();
});

it('keeps manually unblocked permanent blocks in history without reporting an active block', function () {
    Protec::block('203.0.113.1');
    Protec::unblock('203.0.113.1');

    $summary = Protec::ip('203.0.113.1');

    expect($summary->isBlocked)
        ->toBeFalse()
        ->and($summary->isPermanentlyBlocked)
        ->toBeFalse()
        ->and($summary->blockedUntil)
        ->toBeNull()
        ->and($summary->activeBlocks)
        ->toBe(0)
        ->and($summary->totalBlocks)
        ->toBe(1)
        ->and($summary->latestBlock->unblocked_at)
        ->not->toBeNull();
});

it('normalizes IPv6 addresses before querying their records', function () {
    Protec::block('2001:db8::1');

    $summary = Protec::ip('2001:0db8:0000:0000:0000:0000:0000:0001');

    expect($summary->ipAddress)
        ->toBe('2001:db8::1')
        ->and($summary->isBlocked)
        ->toBeTrue()
        ->and($summary->totalBlocks)
        ->toBe(1);
});

it('rejects invalid summary IPs', function (string $ip) {
    expect(fn () => Protec::ip($ip))->toThrow(InvalidArgumentException::class);
})->with(['invalid', '', '203.0.113.1/24']);

it('summarizes configured models using their own table', function () {
    Schema::rename('ip_blocks', 'custom_ip_blocks');
    config()->set('protec.model', CustomBlock::class);
    Protec::block('203.0.113.1');

    $summary = Protec::ip('203.0.113.1');

    expect($summary->latestBlock)
        ->toBeInstanceOf(CustomBlock::class)
        ->and($summary->isBlocked)
        ->toBeTrue()
        ->and($summary->totalBlocks)
        ->toBe(1);
});

it('reports stored blocks independently of request exemptions and package enablement', function () {
    Protec::block('203.0.113.1');
    $this->actingAs(new GenericUser(['id' => 1]));
    config()->set('protec.enabled', false);

    expect(Protec::ip('203.0.113.1')->isBlocked)->toBeTrue();
});
