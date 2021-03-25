<?php


namespace Hubstaff;

use Psr\SimpleCache\CacheInterface;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

class StateManager
{
    const DEFAULT_ISSUER_URL = 'https://account.hubstaff.com';
    const DEFAULT_API_BASE_URL = 'https://api.hubstaff.com/';

    /** @var array */
    public $config;

    /** @var string */
    private $cache_folder;

    /** @var CacheInterface */
    private $cache;

    function __construct(string $cache_folder)
    {
        $this->cache_folder = $cache_folder;

        $this->load();
        if (empty($this->config['issuer_url'])) {
            $this->config['issuer_url'] = self::DEFAULT_ISSUER_URL;
        }
        if (empty($this->config['api_base_url'])) {
            $this->config['api_base_url'] = self::DEFAULT_API_BASE_URL;
        }
        $this->save();
    }

    public function cache() : CacheInterface
    {
        return $this->cache;
    }

    public function setupCache($namespace)
    {
        $fs_cache = new FilesystemAdapter(
            $namespace,
            0,
            $this->cache_folder
        );
        $this->cache = new Psr16Cache($fs_cache);
    }

    public function load()
    {
        $configData = file_get_contents('configState.json');
        $this->config = json_decode($configData, true);
    }

    public function save()
    {
        file_put_contents('configState.json', json_encode($this->config, JSON_PRETTY_PRINT));
    }
}