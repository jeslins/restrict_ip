<?php

namespace Drupal\restrict_ip\Service;

interface RestrictIpServiceInterface
{
	/**
	 * Test if the user is blocked
	 *
	 * @return bool
	 *   TRUE if the user is blocked
	 *   FALSE if the user is not blocked
	 */
	public function userIsBlocked();

	/**
	 * Run all tests to see if the current user should be blocked or not
	 * based on their IP address
	 */
	public function testForBlock();

	/**
	 * Takes a string containing potential IP addresses on separate lines,
	 * strips them of any code comments, trims them, and turns them into a clean array.
	 * Note that the elements may or may not be IP addresses and if validation is necessary,
	 * the array returned from this function should be validated.
	 *
	 * @param string $input
	 *   A string containing new-line separated IP addresses. Can contain code comments
	 *
	 * @return array
	 *   An array of IP addresses parsed from the $input.
	 */
	public function cleanIpAddressInput($input);

	/**
	 * Get the IP address of the current user
	 *
	 * @return string
	 *   The IP address of the current user
	 */
	public function getCurrentUserIp();

	/**
	 * Get the current path that the user is on
	 *
	 * @return string
	 *   The current path
	 */
	public function getCurrentPath();
}
