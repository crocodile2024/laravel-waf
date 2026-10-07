<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Stages;

use Crocodile2024\WAF\Engine\RequestContext;

interface InspectionStage
{
    public function handle(RequestContext $ctx): StageResult;
}
