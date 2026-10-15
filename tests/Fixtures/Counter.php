<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests\Fixtures;

use Livewire\Attributes\Locked;
use Livewire\Component;

class Counter extends Component
{
    public int $count = 0;

    #[Locked]
    public string $lockedValue = 'locked';

    public function increment(): void
    {
        $this->count++;
    }

    public function render(): string
    {
        return '<div>{{ $count }}</div>';
    }
}
