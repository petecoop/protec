<?php

declare(strict_types=1);

namespace Petecoop\Protec\Contracts;

use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Inspection;

interface Detector
{
    public function name(): string;

    public function detect(Inspection $inspection): ?Detection;
}
