<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Models\InspectionProfile;
use Crocodile2024\WAF\Models\ProfileAssignment;
use Crocodile2024\WAF\Models\RateLimitProfile;
use Illuminate\Support\Str;

/**
 * Löst zutreffende Inspektions- und Rate-Limit-Profile auf (Zuweisung per Route/Pfad/Methode
 * oder Middleware-Parameter waf:profile,<name>).
 */
class ProfileResolver
{
    /** @var array<string, array<int, array<string, mixed>>>|null */
    private ?array $rlAssignments = null;

    /** @var array<int, array{assignment: ProfileAssignment, profile: InspectionProfile}>|null */
    private ?array $inspectionAssignments = null;

    public function __construct(
        private readonly ConfigManager $config,
        private readonly RateLimitService $rateLimits,
    ) {}

    public function modeFor(RequestContext $ctx, Mode $global): Mode
    {
        $profile = $this->inspectionProfile($ctx);
        if ($profile !== null && $profile->mode_override !== null) {
            return Mode::fromMixed($profile->mode_override, $global);
        }

        return $global;
    }

    /**
     * @return array<string, mixed>
     */
    public function limitsFor(RequestContext $ctx): array
    {
        $defaults = (array) $this->config->get('limits', []);
        $profile = $this->inspectionProfile($ctx);
        if ($profile !== null && is_array($profile->limits)) {
            return array_merge($defaults, $profile->limits);
        }

        return $defaults;
    }

    public function paranoiaFor(RequestContext $ctx): int
    {
        $profile = $this->inspectionProfile($ctx);

        return $profile?->paranoia_level ?? $this->config->paranoiaLevel();
    }

    /**
     * Liefert eine Geo/ASN-Blockierungsbegründung oder null.
     */
    public function geoDecision(RequestContext $ctx): ?string
    {
        $country = $ctx->attributes->country;
        $asn = $ctx->attributes->asn;

        $allowed = (array) $this->config->get('geoip.allowed_countries', []);
        $denied = (array) $this->config->get('geoip.denied_countries', []);
        $deniedAsns = array_map('intval', (array) $this->config->get('geoip.denied_asns', []));

        $profile = $this->inspectionProfile($ctx);
        if ($profile !== null) {
            $allowed = (array) ($profile->allowed_countries ?: $allowed);
            $denied = (array) ($profile->denied_countries ?: $denied);
            $deniedAsns = array_map('intval', (array) ($profile->denied_asns ?: $deniedAsns));
        }

        if ($country !== null) {
            if ($allowed !== [] && ! in_array($country, $allowed, true)) {
                return 'geo:country_not_allowed';
            }
            if (in_array($country, $denied, true)) {
                return 'geo:country_denied';
            }
        }
        if ($asn !== null && in_array($asn, $deniedAsns, true)) {
            return 'geo:asn_denied';
        }

        return null;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function rateLimitProfiles(RequestContext $ctx): array
    {
        $profiles = [];

        // Vordefinierte Schutzmechanismen (404-Flut etc. werden separat im ResponseStage behandelt)
        foreach ($this->assignmentsFor('rate_limit') as $row) {
            if ($this->assignmentMatches($row['assignment'], $ctx)) {
                $profiles[] = $row['profile'];
            }
        }

        // Middleware-Parameter waf:profile,<name>
        foreach ($ctx->routeMiddleware as $mw) {
            if (str_starts_with($mw, 'profile:')) {
                $name = substr($mw, 8);
                $found = collect($this->rateLimits->activeProfiles())->firstWhere('name', $name);
                if ($found !== null) {
                    $profiles[] = $found;
                }
            }
        }

        return $profiles;
    }

    private function inspectionProfile(RequestContext $ctx): ?InspectionProfile
    {
        foreach ($this->inspectionAssignmentRows() as $row) {
            if ($this->assignmentMatches($row['assignment'], $ctx)) {
                return $row['profile'];
            }
        }

        return null;
    }

    /**
     * @return array<int, array{assignment: ProfileAssignment, profile: InspectionProfile}>
     */
    private function inspectionAssignmentRows(): array
    {
        return $this->inspectionAssignments ??= ProfileAssignment::query()
            ->where('profile_type', 'inspection')
            ->orderBy('priority')
            ->get()
            ->map(function (ProfileAssignment $a): ?array {
                $profile = InspectionProfile::query()->find($a->profile_id);

                return $profile !== null ? ['assignment' => $a, 'profile' => $profile] : null;
            })
            ->filter()
            ->values()
            ->all();
    }

    /**
     * @return array<int, array{assignment: ProfileAssignment, profile: array<string, mixed>}>
     */
    private function assignmentsFor(string $type): array
    {
        $rows = ProfileAssignment::query()->where('profile_type', $type)->orderBy('priority')->get();
        $out = [];
        foreach ($rows as $a) {
            $profile = RateLimitProfile::query()->find($a->profile_id);
            if ($profile !== null && $profile->is_active) {
                $out[] = ['assignment' => $a, 'profile' => [
                    'name' => $profile->name,
                    'key_type' => $profile->key_type,
                    'key_header' => $profile->key_header,
                    'limit' => $profile->limit,
                    'window_seconds' => $profile->window_seconds,
                    'burst' => $profile->burst,
                    'action' => $profile->action,
                ]];
            }
        }

        return $out;
    }

    private function assignmentMatches(ProfileAssignment $a, RequestContext $ctx): bool
    {
        return match ($a->match_type) {
            'route_name' => $ctx->routeName() === $a->match_value,
            'path_pattern' => Str::is($a->match_value, $ctx->path),
            'method' => strtoupper($a->match_value) === $ctx->method,
            default => false,
        };
    }
}
