<?php

declare(strict_types=1);

namespace Petecoop\Protec\Detectors;

use Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException;
use Livewire\Mechanisms\HandleComponents\CorruptComponentPayloadException;
use Petecoop\Protec\Contracts\Detector;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Inspection;

class CorruptLivewirePayload implements Detector
{
    public function detect(Inspection $inspection): ?Detection
    {
        if (! $inspection->request->routeIs('*livewire.update')) {
            return null;
        }

        $exception = $inspection->exception;

        if (
            $exception instanceof CorruptComponentPayloadException
            || $exception instanceof CannotUpdateLockedPropertyException
        ) {
            return new Detection('corrupt-livewire-payload', ['exception' => $exception::class]);
        }

        return null;
    }
}
