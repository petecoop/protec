<?php

declare(strict_types=1);

namespace Petecoop\Protec;

class LivewireComponentNames
{
    public function fromPayload(mixed $component): ?string
    {
        if (! is_array($component) || ! is_string($component['snapshot'] ?? null)) {
            return null;
        }

        $snapshot = json_decode($component['snapshot'], associative: true);
        $name = is_array($snapshot) ? $snapshot['memo']['name'] ?? null : null;

        return is_string($name) ? $this->normalize($name) : null;
    }

    public function normalize(string $name): string
    {
        if (app()->bound('livewire.finder')) {
            return app('livewire.finder')->normalizeName($name) ?? $name;
        }

        return $name;
    }
}
