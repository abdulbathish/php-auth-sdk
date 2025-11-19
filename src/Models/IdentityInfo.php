<?php

namespace MosipAuth\Models;

class IdentityInfo
{
    public $language;
    public $value;

    public function __construct($language, $value)
    {
        $this->language = $language;
        $this->value = $value;
    }

    public function toArray()
    {
        return [
            'language' => $this->language,
            'value' => $this->value,
        ];
    }
}

