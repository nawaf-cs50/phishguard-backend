<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Carbon;

class ScanController extends Controller
{
    public function scan(Request $request): JsonResponse
    {
        $request->validate([
            'url' => ['required', 'url', 'max:2048'],
        ]);

        $normalizedUrl = $this->normalizeUrl($request->input('url'));
        $urlHash = hash('sha256', $normalizedUrl);

        $existing = DB::table('scanned_urls')->where('url_hash', $urlHash)->first();

        if ($existing && Carbon::parse($existing->expires_at)->isFuture()) {
            return response()->json([
                'cached' => true,
                'url' => $existing->url,
                'status' => $existing->status,
                'scanned_at' => $existing->scanned_at,
                'expires_at' => $existing->expires_at,
            ]);
        }

        $vtResult = $this->checkVirusTotal($normalizedUrl);
        $gsbResult = $this->checkSafeBrowsing($normalizedUrl);

        $status = $this->determineStatus($vtResult, $gsbResult);
        $now = now();
        $expiresAt = $now->copy()->addDays(7);

        $record = [
            'url' => $normalizedUrl,
            'url_hash' => $urlHash,
            'status' => $status,
            'vt_result' => json_encode($vtResult),
            'gsb_result' => json_encode($gsbResult),
            'scanned_at' => $now,
            'expires_at' => $expiresAt,
            'updated_at' => $now,
        ];

        if ($existing) {
            DB::table('scanned_urls')->where('id', $existing->id)->update($record);
        } else {
            $record['id'] = (string) \Illuminate\Support\Str::uuid();
            $record['created_at'] = $now;
            DB::table('scanned_urls')->insert($record);
        }

        return response()->json([
            'cached' => false,
            'url' => $normalizedUrl,
            'status' => $status,
            'scanned_at' => $now,
            'expires_at' => $expiresAt,
        ]);
    }

    private function normalizeUrl(string $url): string
    {
        $url = strtolower(trim($url));
        $url = rtrim($url, '/');
        return $url;
    }

    private function checkVirusTotal(string $url): array
    {
        $apiKey = config('services.virustotal.key');

        $response = Http::withHeaders([
            'x-apikey' => $apiKey,
        ])->asForm()->post('https://www.virustotal.com/api/v3/urls', [
            'url' => $url,
        ]);

        if (! $response->successful()) {
            return ['error' => 'virustotal_request_failed', 'status_code' => $response->status()];
        }

        $analysisId = $response->json('data.id');

        $analysis = Http::withHeaders([
            'x-apikey' => $apiKey,
        ])->get("https://www.virustotal.com/api/v3/analyses/{$analysisId}");

        return $analysis->successful() ? $analysis->json() : ['error' => 'analysis_fetch_failed'];
    }

    private function checkSafeBrowsing(string $url): array
    {
        $apiKey = config('services.safe_browsing.key');

        $response = Http::post("https://safebrowsing.googleapis.com/v4/threatMatches:find?key={$apiKey}", [
            'client' => [
                'clientId' => 'phishguard',
                'clientVersion' => '1.0.0',
            ],
            'threatInfo' => [
                'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => [
                    ['url' => $url],
                ],
            ],
        ]);

        return $response->successful() ? $response->json() : ['error' => 'safe_browsing_request_failed'];
    }

    private function determineStatus(array $vtResult, array $gsbResult): string
    {
        if (! empty($gsbResult['matches'])) {
            return 'malicious';
        }

        $stats = $vtResult['data']['attributes']['stats'] ?? null;
        if ($stats) {
            if (($stats['malicious'] ?? 0) > 0) {
                return 'malicious';
            }
            if (($stats['suspicious'] ?? 0) > 0) {
                return 'suspicious';
            }
        }

        return 'safe';
    }
}