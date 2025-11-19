<?php

namespace MosipAuth\Utils;

class Logger
{
    private $logFile;
    private $logFormat;
    private $logLevel;
    private $levels = ['DEBUG' => 0, 'INFO' => 1, 'WARNING' => 2, 'ERROR' => 3, 'CRITICAL' => 4];

    public function __construct($logFile, $logFormat, $logLevel = 'INFO')
    {
        $this->logFile = $logFile;
        $this->logFormat = $logFormat;
        $this->logLevel = $this->levels[$logLevel] ?? 1;
    }

    private function log($level, $message)
    {
        $levelNum = $this->levels[$level] ?? 1;
        if ($levelNum < $this->logLevel) {
            return;
        }

        $timestamp = date('Y-m-d H:i:s');
        $formattedMessage = sprintf($this->logFormat, $timestamp, $level, __CLASS__, $message);
        
        file_put_contents($this->logFile, $formattedMessage . PHP_EOL, FILE_APPEND);
        echo $formattedMessage . PHP_EOL;
    }

    public function debug($message)
    {
        $this->log('DEBUG', $message);
    }

    public function info($message)
    {
        $this->log('INFO', $message);
    }

    public function warning($message)
    {
        $this->log('WARNING', $message);
    }

    public function error($message)
    {
        $this->log('ERROR', $message);
    }

    public function critical($message)
    {
        $this->log('CRITICAL', $message);
    }
}

