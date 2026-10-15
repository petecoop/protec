<?php

declare(strict_types=1);

namespace Petecoop\Protec\Data;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class Inspection
{
    public function __construct(
        public readonly Request $request,
        public readonly ?Response $response = null,
        public readonly ?Throwable $exception = null,
    ) {}
}
