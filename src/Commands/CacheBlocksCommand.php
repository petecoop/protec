<?php

declare(strict_types=1);

namespace Petecoop\Protec\Commands;

use Illuminate\Console\Command;
use Petecoop\Protec\Protec;

class CacheBlocksCommand extends Command
{
    protected $signature = 'protec:cache';

    protected $description = 'Refill the IP block cache from active database records';

    public function handle(Protec $protec): int
    {
        $count = $protec->warmCache();
        $this->info("Block cache refreshed for {$count} IP addresses.");

        return self::SUCCESS;
    }
}
