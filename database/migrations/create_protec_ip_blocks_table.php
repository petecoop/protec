<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('protec_ip_blocks', static function (Blueprint $table): void {
            $table->id();
            $table->ipAddress('ip_address')->unique();
            $table->string('detector');
            $table->string('reason');
            $table->json('context')->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('protec_ip_blocks');
    }
};
