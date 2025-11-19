<?php

namespace MosipAuth\Models;

class DemographicsModel
{
    public $age = '';
    public $dob = '';
    public $name = [];
    public $dobType = [];
    public $gender = [];
    public $phoneNumber = '';
    public $emailId = '';
    public $addressLine1 = [];
    public $addressLine2 = [];
    public $addressLine3 = [];
    public $location1 = [];
    public $location2 = [];
    public $location3 = [];
    public $postalCode = '';
    public $fullAddress = [];
    public $metadata = null;

    public function toArray()
    {
        $data = [
            'age' => $this->age,
            'dob' => $this->dob,
            'name' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->name),
            'dobType' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->dobType),
            'gender' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->gender),
            'phoneNumber' => $this->phoneNumber,
            'emailId' => $this->emailId,
            'addressLine1' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->addressLine1),
            'addressLine2' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->addressLine2),
            'addressLine3' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->addressLine3),
            'location1' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->location1),
            'location2' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->location2),
            'location3' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->location3),
            'postalCode' => $this->postalCode,
            'fullAddress' => array_map(function ($item) {
                return $item instanceof IdentityInfo ? $item->toArray() : $item;
            }, $this->fullAddress),
        ];

        if ($this->metadata !== null) {
            $data['metadata'] = $this->metadata;
        }

        return array_filter($data, function ($value) {
            if (is_array($value)) {
                return !empty($value);
            }
            return $value !== '' && $value !== null;
        });
    }
}

