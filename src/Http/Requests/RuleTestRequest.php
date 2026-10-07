<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class RuleTestRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('viewWAF');
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'method' => ['required', 'string', 'max:10'],
            'path' => ['required', 'string', 'max:4096'],
            'headers' => ['nullable', 'string', 'max:8192'],
            'body' => ['nullable', 'string', 'max:65536'],
        ];
    }
}
