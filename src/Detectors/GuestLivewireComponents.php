<?php

declare(strict_types=1);

namespace Petecoop\Protec\Detectors;

use Petecoop\Protec\Contracts\Detector;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Inspection;
use Petecoop\Protec\LivewireComponentNames;

class GuestLivewireComponents implements Detector
{
    /** @param array<string, mixed> $configuration */
    public function __construct(
        protected array $configuration = [],
    ) {}

    public function detect(Inspection $inspection): ?Detection
    {
        if (
            $inspection->response !== null
            || $inspection->exception !== null
            || ! $inspection->request->routeIs('*livewire.update')
        ) {
            return null;
        }

        $components = $inspection->request->input('components');

        if (! is_array($components) || $components === []) {
            return new Detection('unauthorized-livewire-component', rejectWith: 401);
        }

        foreach ($components as $component) {
            $name = $this->componentName($component);

            if ($name === null || ! in_array($name, $this->components(), strict: true)) {
                return new Detection('unauthorized-livewire-component', ['component' => $name], rejectWith: 401);
            }
        }

        return null;
    }

    /** @return list<string> */
    public function components(): array
    {
        return array_map(
            app(LivewireComponentNames::class)->normalize(...),
            $this->configuration['components'] ?? [],
        );
    }

    protected function componentName(mixed $component): ?string
    {
        return app(LivewireComponentNames::class)->fromPayload($component);
    }
}
