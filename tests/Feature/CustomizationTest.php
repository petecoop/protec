<?php

declare(strict_types=1);

use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Facades\Protec as ProtecFacade;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Protec;
use Petecoop\Protec\Tests\Fixtures\CustomProtec;
use Petecoop\Protec\Tests\Fixtures\ExtendedScanner;
use Petecoop\Protec\Tests\Fixtures\ImmediatePolicy;

it('honours a container-bound Protec subclass in middleware, the facade, and the unblock command', function () {
    $this->app->bind(Protec::class, CustomProtec::class);
    config()->set('protec.detectors.'.ScannerProbe::class.'.options.attempts', 1);

    $this->get('/.env')->assertTooManyRequests()->assertSee('Custom blocked response');
    $block = IpBlock::query()->sole();
    expect($block->ip_address)
        ->toBe('203.0.113.99')
        ->and($block->context['custom'])
        ->toBeTrue()
        ->and(ProtecFacade::getFacadeRoot())
        ->toBeInstanceOf(CustomProtec::class);

    $this->get('/ok')->assertTooManyRequests()->assertSee('Custom blocked response');
    $this->artisan('protec:unblock', ['ip' => '203.0.113.99'])->assertSuccessful();
    $this->get('/ok')->assertOk();
});

it('can replace a scanner through the container to add patterns', function () {
    $this->app->bind(ScannerProbe::class, ExtendedScanner::class);
    config()->set('protec.detectors.'.ScannerProbe::class.'.options.attempts', 1);

    $this->get('/private-admin/users')->assertTooManyRequests();
    expect(IpBlock::query()->sole()->context)->toBe(['pattern' => 'private-admin/*']);
});

it('can select a custom policy for an existing detector', function () {
    $this->freezeSecond();
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy', ImmediatePolicy::class);

    $this->get('/.env')->assertTooManyRequests();
    expect(IpBlock::query()->sole()->expires_at->equalTo(now()->addSeconds(120)))->toBeTrue();
});

it('uses a configured model for persistence, enforcement, and unblocking', function () {
    Illuminate\Support\Facades\Schema::rename('protec_ip_blocks', 'custom_ip_blocks');
    config()->set('protec.model', Petecoop\Protec\Tests\Fixtures\CustomBlock::class);
    config()->set('protec.detectors.'.ScannerProbe::class.'.options.attempts', 1);

    $this->get('/.env')->assertTooManyRequests();
    expect(ProtecFacade::blocked(request()))->toBeInstanceOf(Petecoop\Protec\Tests\Fixtures\CustomBlock::class);
    $this->get('/ok')->assertTooManyRequests();
    $this->artisan('protec:unblock', ['ip' => '127.0.0.1'])->assertSuccessful();
    $this->get('/ok')->assertOk();
    $this->assertDatabaseCount('custom_ip_blocks', 1);
});

it('can exempt requests through a configured exemption', function () {
    config()->set('protec.exemptions', [Petecoop\Protec\Tests\Fixtures\ExemptStatusRequests::class]);
    config()->set('protec.detectors.'.ScannerProbe::class.'.options.attempts', 1);

    $this->get('/.env')->assertTooManyRequests();
    $this->get('/ok')->assertOk();
    $this->get('/counter')->assertTooManyRequests();
});

it('honours the subclass response through Livewire exception handling', function () {
    $this->app->bind(Protec::class, CustomProtec::class);
    config()->set('protec.detectors.'.Petecoop\Protec\Detectors\CorruptLivewirePayload::class.'.options.attempts', 1);
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;

    $this->postJson(Livewire\Livewire::getUpdateUri(), $this->payload($snapshot), [
        'X-Livewire' => 'true',
    ])
        ->assertTooManyRequests()
        ->assertSee('Custom blocked response');
    expect(IpBlock::query()->sole()->ip_address)->toBe('203.0.113.99');
});
