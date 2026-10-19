<?php

declare(strict_types=1);

namespace Petecoop\Protec;

use Livewire\Exceptions\MethodNotFoundException;
use Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException;
use Livewire\Mechanisms\HandleComponents\CorruptComponentPayloadException;
use Throwable;

class LivewireExceptions
{
    /** @return list<class-string<Throwable>> */
    public function classes(): array
    {
        return [
            CorruptComponentPayloadException::class,
            CannotUpdateLockedPropertyException::class,
            MethodNotFoundException::class,
        ];
    }

    public function matches(?Throwable $exception): bool
    {
        foreach ($this->classes() as $class) {
            if ($exception instanceof $class) {
                return true;
            }
        }

        return false;
    }
}
