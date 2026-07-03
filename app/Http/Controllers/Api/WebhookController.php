<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class WebhookController extends Controller
{
    /**
     * Incoming webhook: AI Agent pushes extracted threat entities here.
     */
    public function receiveThreatIntel(Request $request): JsonResponse
    {
        if (! $this->verifySignature($request)) {
            return response()->json(['error' => 'Invalid signature'], 401);
        }

        $validated = $request->validate([
            'scanned_url_id' => ['required', 'uuid', 'exists:scanned_urls,id'],
            'entities' => ['required', 'array', 'min:1'],
            'entities.*.entity_type' => ['required', 'string', 'in:iban,wallet,payment_gateway'],
            'entities.*.entity_value' => ['required', 'string'],
            'entities.*.confidence' => ['nullable', 'numeric', 'between:0,1'],
            'entities.*.source' => ['nullable', 'string'],
        ]);

        $now = now();
        $rows = collect($validated['entities'])->map(function ($entity) use ($validated, $now) {
            return [
                'id' => (string) Str::uuid(),
                'scanned_url_id' => $validated['scanned_url_id'],
                'entity_type' => $entity['entity_type'],
                'entity_value' => $entity['entity_value'],
                'confidence' => $entity['confidence'] ?? null,
                'source' => $entity['source'] ?? 'ai_agent',
                'created_at' => $now,
                'updated_at' => $now,
            ];
        })->toArray();

        DB::table('threat_intelligence')->insert($rows);

        // If any IBAN/wallet found, mark the URL as malicious and fire outgoing alert.
        $hasCriticalEntity = collect($validated['entities'])
            ->whereIn('entity_type', ['iban', 'wallet'])
            ->isNotEmpty();

        if ($hasCriticalEntity) {
            DB::table('scanned_urls')
                ->where('id', $validated['scanned_url_id'])
                ->update(['status' => 'malicious', 'updated_at' => $now]);

            $this->sendMaliciousAlert($validated['scanned_url_id'], $validated['entities']);
        }

        return response()->json(['status' => 'received', 'inserted' => count($rows)]);
    }

    /**
     * Outgoing webhook: notify n8n / downstream systems of a malicious finding.
     */
    private function sendMaliciousAlert(string $scannedUrlId, array $entities): void
    {
        $n8nUrl = config('services.n8n.webhook_url');

        if (! $n8nUrl) {
            Log::warning('N8N_WEBHOOK_URL not configured, skipping outgoing alert.');
            return;
        }

        $payload = [
            'scanned_url_id' => $scannedUrlId,
            'entities' => $entities,
            'triggered_at' => now()->toIso8601String(),
        ];

        $signature = hash_hmac('sha256', json_encode($payload), config('services.webhook.secret'));

        try {
            Http::withHeaders(['X-Signature' => $signature])
                ->timeout(5)
                ->retry(3, 200)
                ->post($n8nUrl, $payload);
        } catch (\Throwable $e) {
            Log::error('Failed to send outgoing webhook: ' . $e->getMessage());
        }
    }

    /**
     * Verify HMAC signature on incoming webhook requests.
     */
    private function verifySignature(Request $request): bool
    {
        $signature = $request->header('X-Signature');
        $secret = config('services.webhook.secret');

        if (! $signature || ! $secret) {
            return false;
        }

        $expected = hash_hmac('sha256', $request->getContent(), $secret);

        return hash_equals($expected, $signature);
    }
}