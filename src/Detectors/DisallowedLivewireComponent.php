<?php

declare(strict_types=1);

namespace Petecoop\Protec\Detectors;

use Petecoop\Protec\Contracts\Detector;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Inspection;
use Petecoop\Protec\LivewireComponentNames;

class DisallowedLivewireComponent implements Detector
{
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
            return new Detection('unauthorized-livewire-component');
        }

        foreach ($components as $component) {
            $name = $this->componentName($component);

            if ($name === null || ! in_array($name, $this->guestComponents(), strict: true)) {
                return new Detection('unauthorized-livewire-component', ['component' => $name]);
            }

            if (in_array($name, $this->readOnlyComponents(), strict: true) && ($component['updates'] ?? []) !== []) {
                return new Detection('unauthorized-livewire-component', ['component' => $name]);
            }
        }

        return null;
    }

    /** @return list<string> */
    public function guestComponents(): array
    {
        return array_map(
            app(LivewireComponentNames::class)->normalize(...),
            config('protec.livewire.guest_components', []),
        );
    }

    /** @return list<string> */
    public function readOnlyComponents(): array
    {
        return array_map(
            app(LivewireComponentNames::class)->normalize(...),
            config('protec.livewire.read_only_components', []),
        );
    }

    protected function componentName(mixed $component): ?string
    {
        return app(LivewireComponentNames::class)->fromPayload($component);
    }
}
