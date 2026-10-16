<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Detectors\CorruptLivewirePayload;
use Petecoop\Protec\Detectors\GuestLivewireComponents;
use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Events\ActivityDetected;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Tests\Fixtures\NamedScanner;

it('uses short detector names in blocks and activity events', function (string $class, string $name) {
    Event::fake([ActivityDetected::class]);

    $block = Protec::record(request(), new Detection('test'), new Limit(attempts: 1), $class);

    expect($block->detector)->toBe($name);
    Event::assertDispatched(ActivityDetected::class, fn (ActivityDetected $event): bool => $event->detector === $name);
})->with([
    [ScannerProbe::class,            'scanner-probe'],
    [CorruptLivewirePayload::class,  'corrupt-livewire-payload'],
    [GuestLivewireComponents::class, 'guest-livewire-components'],
]);

it('shares the rate limit when recording by detector class or short name', function () {
    $limit = new Limit(attempts: 2);

    expect(Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class))->toBeNull();
    expect(Protec::record(request(), new Detection('test'), $limit, 'scanner-probe')->detector)
        ->toBe('scanner-probe');
});

it('uses an overridden name while finding policy and escalation by the configured class', function () {
    $this->freezeSecond();
    $this->app->bind(ScannerProbe::class, NamedScanner::class);
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy', [
        'attempts' => 2,
        'block_for' => 1,
    ]);
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => '8h',
        'block_for' => null,
    ]);

    $this->get('/.env')->assertNotFound();
    $this->get('/.env')->assertTooManyRequests();
    $block = IpBlock::query()->sole();
    expect($block->detector)
        ->toBe('custom-scanner')
        ->and($block->reason)
        ->toBe('custom-scanner')
        ->and($block->block_history)
        ->toBe(['custom-scanner' => [now()->timestamp]]);

    $this->travel(1)->seconds();
    $this->get('/.env')->assertNotFound();
    $this->get('/.env')->assertTooManyRequests();
    $block->refresh();
    expect($block->expires_at)->toBeNull()->and($block->block_history['custom-scanner'])->toHaveCount(2);

    expect(Protec::unblock('127.0.0.1'))->toBeTrue();
    $this->get('/.env')->assertNotFound();
});
