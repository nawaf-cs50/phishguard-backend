<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('threat_intelligence', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->foreignUuid('scanned_url_id')->constrained('scanned_urls')->cascadeOnDelete();
            $table->string('entity_type');   // 'iban', 'wallet', 'payment_gateway'
            $table->text('entity_value');
            $table->decimal('confidence', 3, 2)->nullable();
            $table->string('source')->nullable();
            $table->timestampsTz();

            $table->index(['entity_type', 'entity_value']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('threat_intelligence');
    }
};