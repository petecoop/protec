<?php

declare(strict_types=1);

namespace Petecoop\Protec\Detectors;

use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Petecoop\Protec\Contracts\Detector;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Inspection;

class ScannerProbe implements Detector
{
    /** @param array<string, mixed> $configuration */
    public function __construct(
        protected array $configuration = [],
    ) {}

    public function name(): string
    {
        return 'scanner-probe';
    }

    public function detect(Inspection $inspection): ?Detection
    {
        if ($inspection->response?->getStatusCode() !== 404) {
            return null;
        }

        $path = Str::lower(ltrim(rawurldecode($inspection->request->getPathInfo()), characters: '/'));

        if ($this->isExcepted($path)) {
            return null;
        }

        foreach ($this->patterns() as $pattern) {
            if (Str::is(Str::lower($pattern), $path)) {
                return new Detection($this->name(), ['pattern' => $pattern]);
            }
        }

        return null;
    }

    /** @return list<string> */
    public function patterns(): array
    {
        return Arr::flatten($this->configuration['patterns'] ?? []);
    }

    protected function isExcepted(string $path): bool
    {
        foreach ($this->configuration['except'] ?? [] as $pattern) {
            if (Str::is(Str::lower($pattern), $path)) {
                return true;
            }
        }

        return false;
    }
}
