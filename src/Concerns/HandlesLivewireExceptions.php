<?php

declare(strict_types=1);

namespace Petecoop\Protec\Concerns;

use Illuminate\Http\Request;
use Petecoop\Protec\Data\Inspection;
use Petecoop\Protec\Detectors\CorruptLivewirePayload;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

trait HandlesLivewireExceptions
{
    public function isLivewireTampering(Inspection $inspection): bool
    {
        return $this->livewireTamperingConfiguration($inspection) !== null;
    }

    /** @return array<string, mixed>|null */
    protected function livewireTamperingConfiguration(Inspection $inspection): ?array
    {
        if (! $this->shouldInspect($inspection->request)) {
            return null;
        }

        foreach ($this->detectors()->definitions() as $class => $definition) {
            $detector = $this->detectors()->detector($class);

            if ($detector instanceof CorruptLivewirePayload && $detector->detect($inspection) !== null) {
                return $definition;
            }
        }

        return null;
    }

    public function handleException(Response $response, Throwable $exception, Request $request): Response
    {
        return $this->inspect(new Inspection($request, $response, $exception)) ?? $response;
    }

    public function shouldIgnoreException(Throwable $exception, Request $request): bool
    {
        $configuration = $this->livewireTamperingConfiguration(new Inspection($request, exception: $exception));

        return $configuration !== null && ! ($configuration['report'] ?? false);
    }
}
