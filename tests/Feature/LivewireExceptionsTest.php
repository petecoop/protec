<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Livewire\Mechanisms\HandleComponents\CorruptComponentPayloadException;
use Petecoop\Protec\Data\Inspection;
use Petecoop\Protec\DetectorRegistry;
use Petecoop\Protec\Detectors\CorruptLivewirePayload;
use Petecoop\Protec\LivewireExceptions;
use Petecoop\Protec\Protec;

it('uses the same container-resolved exception catalogue for detection and reporting', function () {
    $this->app->instance(LivewireExceptions::class, new class extends LivewireExceptions {
        public function classes(): array
        {
            return [RuntimeException::class];
        }
    });
    $request = Request::create('/livewire/update', method: 'POST');
    $request->setRouteResolver(
        static fn (): Route => (new Route(['POST'], 'livewire/update', []))->name('livewire.update'),
    );
    $detector = app(DetectorRegistry::class)->detector(CorruptLivewirePayload::class);
    $protec = app(Protec::class);
    $exception = new RuntimeException('Custom Livewire failure');

    expect($detector->detect(new Inspection($request, exception: $exception))->context)
        ->toBe(['exception' => RuntimeException::class])
        ->and($protec->shouldIgnoreException($exception, $request))
        ->toBeTrue();

    $removed = new CorruptComponentPayloadException;
    expect($detector->detect(new Inspection($request, exception: $removed)))
        ->toBeNull()
        ->and($protec->shouldIgnoreException($removed, $request))
        ->toBeFalse();

    config()->set('protec.detectors.'.CorruptLivewirePayload::class.'.report', true);
    expect($protec->shouldIgnoreException($exception, $request))->toBeFalse();
});
