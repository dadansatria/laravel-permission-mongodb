<?php

namespace Dadansatria\Permission\Exceptions;

use InvalidArgumentException;
use Throwable;
use function app;
use function config;

/**
 * Class DadansatriaException
 * @package Dadansatria\Permission\Exceptions
 */
class DadansatriaException extends InvalidArgumentException
{
    /**
     * DadansatriaException constructor.
     *
     * @param string|null $message
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(string $message = null, int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);

        if (config('permission.log_registration_exception')) {
            $logger = app('log');
            $logger->alert($message);
        }
    }
}
