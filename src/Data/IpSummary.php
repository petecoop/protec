<?php

declare(strict_types=1);

namespace Petecoop\Protec\Data;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Carbon;
use JsonSerializable;
use Petecoop\Protec\Models\IpBlock;

/** @implements Arrayable<string, mixed> */
class IpSummary implements Arrayable, JsonSerializable
{
    public readonly bool $isBlocked;

    public readonly bool $isPermanentlyBlocked;

    public function __construct(
        public readonly string $ipAddress,
        public readonly int $totalBlocks,
        public readonly int $activeBlocks,
        public readonly ?Carbon $blockedUntil,
        public readonly ?IpBlock $latestBlock,
    ) {
        $this->isBlocked = $activeBlocks > 0;
        $this->isPermanentlyBlocked = $this->isBlocked && $blockedUntil === null;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'ip_address' => $this->ipAddress,
            'is_blocked' => $this->isBlocked,
            'is_permanently_blocked' => $this->isPermanentlyBlocked,
            'blocked_until' => $this->blockedUntil?->toISOString(),
            'total_blocks' => $this->totalBlocks,
            'active_blocks' => $this->activeBlocks,
            'latest_block' => $this->latestBlock?->toArray(),
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
