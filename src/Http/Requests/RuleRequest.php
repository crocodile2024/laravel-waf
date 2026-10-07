<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Requests;

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Engine\Rules\RuleCompiler;
use Crocodile2024\WAF\Engine\Scoring\Severity;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Validator;

class RuleRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('manageWAF');
    }

    protected function prepareForValidation(): void
    {
        // Bedingungen/Aktion/Tags kommen aus dem UI als JSON-Strings.
        $this->merge([
            'conditions' => $this->decodeJson($this->input('conditions')),
            'action' => $this->decodeJson($this->input('action')),
            'tags' => $this->decodeJson($this->input('tags')) ?: $this->input('tags', []),
            'transforms' => $this->decodeJson($this->input('transforms')) ?: $this->input('transforms', []),
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'code' => ['required', 'string', 'max:64', 'regex:/^[A-Z0-9][A-Z0-9_\-]{2,63}$/'],
            'name' => ['required', 'string', 'max:255'],
            'description' => ['nullable', 'string', 'max:2000'],
            'severity' => ['required', 'in:'.implode(',', Severity::values())],
            'paranoia_level' => ['required', 'integer', 'between:1,4'],
            'priority' => ['required', 'integer', 'between:0,1000'],
            'phase' => ['required', 'in:request,response'],
            'mode_override' => ['nullable', 'in:'.implode(',', Mode::values())],
            'is_active' => ['boolean'],
            'tags' => ['nullable', 'array'],
            'tags.*' => ['string', 'max:64'],
            'transforms' => ['nullable', 'array'],
            'conditions' => ['required', 'array'],
            'action' => ['required', 'array'],
            'action.type' => ['required', 'in:'.implode(',', RuleCompiler::ACTIONS)],
        ];
    }

    public function withValidator(Validator $validator): void
    {
        $validator->after(function (Validator $validator): void {
            $errors = (new RuleCompiler)->validate($this->toRule('custom'));
            foreach ($errors as $error) {
                $validator->errors()->add('conditions', $error);
            }
        });
    }

    /**
     * @return array<string, mixed>
     */
    public function toRule(string $source): array
    {
        return [
            'code' => (string) $this->input('code'),
            'source' => $source,
            'name' => (string) $this->input('name'),
            'description' => $this->input('description'),
            'severity' => (string) $this->input('severity'),
            'paranoia_level' => (int) $this->input('paranoia_level', 1),
            'priority' => (int) $this->input('priority', 500),
            'phase' => (string) $this->input('phase', 'request'),
            'conditions' => $this->decodeJson($this->input('conditions')),
            'transforms' => (array) $this->input('transforms', []),
            'action' => $this->decodeJson($this->input('action')),
            'mode_override' => $this->input('mode_override') ?: null,
            'tags' => array_values(array_filter((array) $this->input('tags', []))),
            'is_active' => (bool) $this->boolean('is_active'),
        ];
    }

    private function decodeJson(mixed $value): mixed
    {
        if (is_string($value)) {
            $decoded = json_decode($value, true);

            return is_array($decoded) ? $decoded : [];
        }

        return $value;
    }
}
