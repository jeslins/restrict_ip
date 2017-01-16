<?php

namespace Drupal\restrict_ip\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Path\CurrentPathStack;
use Drupal\Core\Session\AccountProxyInterface;
use Symfony\Component\HttpFoundation\RequestStack;

class RestrictIpService implements RestrictIpServiceInterface
{
	/**
	 * Indicates whether or not the user should be blocked
	 *
	 * @var bool
	 */
	private $blocked;

	/**
	 * The current user
	 *
	 * @var \Drupal\Core\Session\AccountProxyInterface
	 */
	protected $currentUser;

	/**
	 * The current path
	 *
	 * @var string
	 */
	protected $currentPath;

	/**
	 * The Restrict IP configuration settings
	 *
	 * @var \Drupal\Core\Config\ImmutableConfig
	 */
	protected $config;

	/**
	 * The current user's IP address
	 *
	 * @var string
	 */
	private $currentUserIp;

	/**
	 * Constructs a RestrictIpService object
	 *
	 * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
	 *   The current user
	 * @param \Drupal\Core\Path\CurrentPathStack $currentPathStack
	 *   The current path stack
	 * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
	 *   The Config Factory service
	 * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
	 *   The current HTTP request
	 */
	public function __construct(AccountProxyInterface $currentUser, CurrentPathStack $currentPathStack, ConfigFactoryInterface $configFactory, RequestStack $requestStack)
	{
		$this->currentUser = $currentUser;

		$this->currentPath = strtolower($currentPathStack->getPath());
		$this->config = $configFactory->get('restrict_ip.settings');
		$this->currentUserIp = $requestStack->getCurrentRequest()->getClientIp();
	}

	/**
	 * {@inheritdoc}
	 */
	public function userIsBlocked()
	{
		if($this->allowAccessByPermission())
		{
			return FALSE;
		}

		return $this->blocked;
	}

	/**
	 * {@inheritdoc}
	 */
	public function testForBlock()
	{
		$this->blocked = FALSE;

		if($this->config->get('enable'))
		{
			$this->blocked = TRUE;

			// We don't want to check IP on CLI (likely drush) requests
			if(PHP_SAPI != 'cli')
			{
				$access_denied = TRUE;
				if($this->allowAccessWhitelistedPath())
				{
					$access_denied = FALSE;
				}
				elseif($this->allowAccessBlacklistedPath())
				{
					$access_denied = FALSE;
				}
				elseif($this->allowAccessWhitelistedIp())
				{
					$access_denied = FALSE;
				}

				// If the user has been denied access
				if($access_denied)
				{
					$_SESSION['restrict_ip'] = TRUE;
				}
				else
				{
					$this->blocked = FALSE;
				}
			}
		}
	}

	/**
	 * {@inheritdoc}
	 */
	public function cleanIpAddressInput($input)
	{
		$ip_addresses = trim($input);
		$ip_addresses = preg_replace('/(\/\/|#).+/', '', $ip_addresses);
		$ip_addresses = preg_replace('~/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/~', '', $ip_addresses);

		$addresses = explode(PHP_EOL, $ip_addresses);

		$return = [];
		foreach($addresses as $ip_address)
		{
			$trimmed = trim($ip_address);
			if(strlen($trimmed))
			{
				$return[] = $trimmed;
			}
		}

		return $return;
	}

	/**
	 * {@inheritdoc}
	 */
	public function getCurrentUserIp()
	{
		return $this->currentUserIp;
	}

	/**
	 * {@inheritdoc}
	 */
	public function getCurrentPath()
	{
		return $this->currentPath;
	}

	/**
	 * Test to see if access should be granted based on 
	 */
	private function allowAccessByPermission()
	{
		static $allow_access;

		if(is_null($allow_access))
		{
			$allow_access = FALSE;

			if($this->config->get('allow_role_bypass'))
			{
				$current_path = strtolower($this->currentPath);
				if($this->currentUser->hasPermission('bypass ip restriction') || in_array($current_path, array('/user', '/user/login', '/user/password', '/user/logout')) || strpos($current_path, '/user/reset/') === 0)
				{
					$allow_access = TRUE;
				}
			}
		}

		return $allow_access;
	}

	/**
	 * Test if the current path is allowed based on whitelist settings
	 */
	private function allowAccessWhitelistedPath()
	{
		$allow_access = FALSE;
		if($this->config->get('white_black_list') == 1)
		{
			$whitelisted_pages = $this->config->get('page_whitelist');
			if(count($whitelisted_pages) && in_array($this->currentPath, $whitelisted_pages))
			{
				$allow_access = TRUE;
			}
		}

		return $allow_access;
	}

	/**
	 * Test if the current path is allowed based on blacklist settings
	 */
	private function allowAccessBlacklistedPath()
	{
		$allow_access = FALSE;
		if($this->config->get('white_black_list') == 2)
		{
			$blacklisted_pages = $this->config->get('page_blacklist');
			if(count($blacklisted_pages) && !in_array($this->currentPath, $blacklisted_pages))
			{
				$allow_access = TRUE;
			}
		}

		return $allow_access;
	}

	/**
	 * Test to see if the current user has a whitelisted IP address
	 */
	private function allowAccessWhitelistedIp()
	{
		$ip_whitelist = $this->buildWhitelistedIpAddresses();

		if(count($ip_whitelist))
		{
			foreach($ip_whitelist as $whitelisted_address)
			{
				if($this->testWhitelistedIp($whitelisted_address))
				{
					return TRUE;
				}
			}
		}

		return FALSE;
	}

	/**
	 * Build an array of whitelisted IP addresses based on site settings
	 */
	private function buildWhitelistedIpAddresses()
	{
		// Get the value saved to the system, and turn it into an array of IP addresses.
		$ip_addresses = $this->config->get('address_list');

		// Add any whitelisted IPs from the settings.php file to the whitelisted array
		$ip_whitelist = $this->config->get('ip_whitelist');
		if(count($ip_whitelist))
		{
			$ip_addresses = array_merge($ip_addresses, $ip_whitelist);
		}

		return $ip_addresses;
	}

	/**
	 * Test an ip address to see if the current user should be whitelisted based on
	 * that address.
	 *
	 * @param $whitelisted_address
	 *   The address to check
	 *
	 * @return bool
	 *   TRUE if the user should be allowed access based on the current IP
	 *   FALSE if they should not be allowed access based on the current IP
	 */
	private function testWhitelistedIp($whitelisted_ip)
	{
		// Check if the given IP address matches the current user
		if($whitelisted_ip == $this->getCurrentUserIp())
		{
			return TRUE;
		}

		$pieces = explode('-', $whitelisted_ip);
		// We only need to continue checking this IP address
		// if it is a range of addresses
		if(count($pieces) == 2)
		{
			$start_ip = $pieces[0];
			$end_ip = $pieces[1];
			$start_pieces = explode('.', $start_ip);
			// If there are not 4 sections to the IP then its an invalid
			// IPv4 address, and we don't need to continue checking
			if(count($start_pieces) === 4)
			{
				$user_pieces = explode('.', $this->currentUserIp);
				// We compare the first three chunks of the first IP address
				// With the first three chunks of the user's IP address
				// If they are not the same, then the IP address is not within
				// the range of IPs
				for($i = 0; $i < 3; $i++)
				{
					if((int) $user_pieces[$i] !== (int) $start_pieces[$i])
					{
						// One of the chunks has failed, so we can stop
						// checking this range
						return FALSE;
					}
				}

				// The first three chunks have past testing, so now we check the
				// range given to see if the final chunk is in this range
				// First we get the start of the range
				$start_final_chunk = (int) array_pop($start_pieces);
				$end_pieces = explode('.', $end_ip);
				// Then we get the end of the range. This will work
				// whether the user has entered XXX.XXX.XXX.XXX - XXX.XXX.XXX.XXX
				// or XXX.XXX.XXX.XXX-XXX
				$end_final_chunk = (int) array_pop($end_pieces);
				// Now we get the user's final chunk
				$user_final_chunk = (int) array_pop($user_pieces);
				// And finally we check to see if the user's chunk lies in that range
				if($user_final_chunk >= $start_final_chunk && $user_final_chunk <= $end_final_chunk)
				{
					// The user's IP lies in the range, so we don't grant access
					return TRUE;
				}
			}
		}

		return FALSE;
	}
}
