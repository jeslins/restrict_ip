<?php

namespace Drupal\Tests\restrict_ip\Service;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Tests\UnitTestCase;
use Drupal\restrict_ip\Service\RestrictIpService;

/**
 * @coversDefaultClass \Drupal\restrict_ip\Service\RestrictIpService
 * @group restrict_ip
 */
class RestrictIpServiceTest extends UnitTestCase
{
	protected $currentUser;
	protected $currentPathStack;
	protected $requestStack;
	protected $request;

	/**
	 * {@inheritdoc}
	 */
	public function setUp()
	{
		$this->currentUser = $this->getMockBuilder('Drupal\Core\Session\AccountProxyInterface')
			->disableOriginalConstructor()
			->getMock();

		$this->currentPathStack = $this->getMockBuilder('Drupal\Core\Path\CurrentPathStack')
			->disableOriginalConstructor()
			->getMock();

		$this->requestStack = $this->getMockBuilder('Symfony\Component\HttpFoundation\RequestStack')
			->disableOriginalConstructor()
			->getMock();

		$this->request = $this->getMockBuilder('Symfony\Component\HttpFoundation\Request')
			->disableOriginalConstructor()
			->getMock();
	}

	/**
	 * @covers ::userIsBlocked
	 */
	public function testUserHasRoleBypassPermission()
	{
		$this->currentUser->expects($this->at(0))
			->method('hasPermission')
			->with('bypass ip restriction')
			->willReturn(TRUE);

		$this->currentPathStack->expects($this->at(0))
			->method('getPath')
			->willReturn('/restricted/path');

		$this->request->expects($this->at(0))
			->method('getClientIp')
			->willReturn('::1');

		$this->requestStack->expects($this->at(0))
			->method('getCurrentRequest')
			->willReturn($this->request);

		$configFactory = $this->getConfigFactory(['allow_role_bypass' => TRUE]);

		$restrictIpService = New RestrictIpService($this->currentUser, $this->currentPathStack, $configFactory, $this->requestStack);

		$user_is_blocked = $restrictIpService->userIsBlocked();
		$this->assertFalse($user_is_blocked, 'User is not blocked when they have the permission bypass access restriction');
	}
	
	/**
	 * @covers ::userIsBlocked
	 * @dataProvider pathInAllowedPathsDataProvider
	 */
	public function testPathInAllowedPaths($path, $expectedResult)
	{
		$this->currentUser->expects($this->at(0))
			->method('hasPermission')
			->willReturn(FALSE);

		$this->currentPathStack->expects($this->at(0))
			->method('getPath')
			->willReturn($path);

		$this->request->expects($this->at(0))
			->method('getClientIp')
			->willReturn('::1');

		$this->requestStack->expects($this->at(0))
			->method('getCurrentRequest')
			->willReturn($this->request);

		$configFactory = $this->getConfigFactory(['allow_role_bypass' => TRUE]);

		$restrictIpService = New RestrictIpService($this->currentUser, $this->currentPathStack, $configFactory, $this->requestStack);

		$user_is_blocked = $restrictIpService->userIsBlocked();
		$this->assertSame($expectedResult, $user_is_blocked, 'User is not blocked when they are on the allowed path: ' . $path);
	}

	/**
	 * Data provider for testPathInAllowedPaths()
	 */
	public function pathInAllowedPathsDataProvider()
	{
		return [
			['/user', FALSE],
			['/user/login', FALSE],
			['/user/password', FALSE],
			['/user/logout', FALSE],
			['/user/reset/something', FALSE],
			['/invalid/path', NULL],
		];
	}

	/**
	 * @covers ::testForBlock
	 * @dataProvider blockWhitelistDataProvider
	 */
	public function testTestForBlockWhitelist($pathToCheck, $expectedResult, $message)
	{
		$this->currentPathStack->expects($this->at(0))
			->method('getPath')
			->willReturn($pathToCheck);

		$this->request->expects($this->at(0))
			->method('getClientIp')
			->willReturn('::1');

		$this->requestStack->expects($this->at(0))
			->method('getCurrentRequest')
			->willReturn($this->request);

		$configFactory = $this->getConfigFactory([
			'enable' => TRUE,
			'white_black_list' => 1,
			'page_whitelist' => ['/some/path'],
		]);

		$restrictIpService = New RestrictIpService($this->currentUser, $this->currentPathStack, $configFactory, $this->requestStack);
		$restrictIpService->testForBlock(TRUE);

		$this->assertSame($expectedResult, $restrictIpService->userIsBlocked(), $message);
	}

	/**
	 * Data provider for testTestForBlockWhitelist()
	 */
	public function blockWhitelistDataProvider()
	{
		return [
			['/some/path', FALSE, 'User is allowed on whitelisted path'],
			['/some/other/path', TRUE, 'User is blocked on non-whitelisted path'],
		];
	}

	/**
	 * @covers ::testForBlock
	 * @dataProvider blockBlacklistDataProvider
	 */
	public function testTestForBlockBlacklist($pathToCheck, $expectedResult, $message)
	{
		$this->currentPathStack->expects($this->at(0))
			->method('getPath')
			->willReturn($pathToCheck);

		$this->request->expects($this->at(0))
			->method('getClientIp')
			->willReturn('::1');

		$this->requestStack->expects($this->at(0))
			->method('getCurrentRequest')
			->willReturn($this->request);

		$configFactory = $this->getConfigFactory([
			'enable' => TRUE,
			'white_black_list' => 2,
			'page_blacklist' => ['/some/path'],
		]);

		$restrictIpService = New RestrictIpService($this->currentUser, $this->currentPathStack, $configFactory, $this->requestStack);
		$restrictIpService->testForBlock(TRUE);

		$this->assertSame($expectedResult, $restrictIpService->userIsBlocked(), $message);
	}

	/**
	 * Data provider for testTestForBlockBlacklist()
	 */
	public function blockBlacklistDataProvider()
	{
		return [
			['/some/path', TRUE, 'User is blocked on blacklisted path'],
			['/some/other/path', FALSE, 'User is not blocked on non-blacklisted path'],
		];
	}

	/**
	 * @covers ::testForBlock
	 * @dataProvider blockIpAddressDataProvider
	 */
	public function testTestForBlockIpAddress($ipAddressToCheck, $configFactory, $expectedResult, $message)
	{
		$this->currentPathStack->expects($this->at(0))
			->method('getPath')
			->willReturn('/some/path');

		$this->request->expects($this->at(0))
			->method('getClientIp')
			->willReturn('::1');

		$this->requestStack->expects($this->at(0))
			->method('getCurrentRequest')
			->willReturn($this->request);

		$restrictIpService = New RestrictIpService($this->currentUser, $this->currentPathStack, $configFactory, $this->requestStack);
		$restrictIpService->testForBlock(TRUE);

		$this->assertSame($expectedResult, $restrictIpService->userIsBlocked(), $message);
	}

	/**
	 * Data provider for testTestForBlockIpAddress()
	 */
	public function blockIpAddressDataProvider()
	{
		return [
			['::1', $this->getConfigFactory([
				'enable' => TRUE,
				'white_black_list' => 0,
				'address_list' => ['::1'],
				'ip_whitelist' => [],
			]), FALSE, 'User is not blocked when IP address has been whitelisted through admin interface'],
			['::1', $this->getConfigFactory([
				'enable' => TRUE,
				'white_black_list' => 0,
				'address_list' => ['::2'],
				'ip_whitelist' => [],
			]), TRUE, 'User is blocked when IP address has not been whitelisted through admin interface'],
			['::1', $this->getConfigFactory([
				'enable' => TRUE,
				'white_black_list' => 0,
				'address_list' => [],
				'ip_whitelist' => ['::1'],
			]), FALSE, 'User is not blocked when IP address has been whitelisted in settings.php'],
			['::1', $this->getConfigFactory([
				'enable' => TRUE,
				'white_black_list' => 0,
				'address_list' => [],
				'ip_whitelist' => ['::2'],
			]), TRUE, 'User is blocked when IP address has not been whitelisted through settings.php'],
		];
	}

	/**
	 * @covers ::cleanIpAddressInput
	 * @dataProvider cleanIpAddressInputDataProvider
	 */
	public function testCleanIpAddressInput($input, $expectedResult, $message)
	{
		$this->currentPathStack->expects($this->at(0))
			->method('getPath')
			->willReturn('/some/path');

		$this->request->expects($this->at(0))
			->method('getClientIp')
			->willReturn('::1');

		$this->requestStack->expects($this->at(0))
			->method('getCurrentRequest')
			->willReturn($this->request);
		
		$configFactory = $this->getConfigFactory([]);

		$restrictIpService = New RestrictIpService($this->currentUser, $this->currentPathStack, $configFactory, $this->requestStack);

		$this->assertSame($expectedResult, $restrictIpService->cleanIpAddressInput($input), $message);
	}

	/**
	 * Data provider for testCleanIpAddressInput()
	 */
	public function cleanIpAddressInputDataProvider()
	{
		return [
			['111.111.111.111
			111.111.111.112',
			['111.111.111.111', '111.111.111.112'],
			'Items properly parsed when separated by new lines'],
			['// This is a comment
			111.111.111.111',
			['111.111.111.111'],
			'Items properly parsed when comment starting with // exists'],
			['# This is a comment
			111.111.111.111',
			['111.111.111.111'],
			'Items properly parsed when comment starting with # exists'],
			['/**
			 *This is a comment
			 */
			111.111.111.111',
			['111.111.111.111'],
			'Items properly parsed when multiline comment exists'],
		];
	}

	/**
	 * @covers ::getCurrentUserIp
	 */
	public function testGetCurrentUserIp()
	{
		$this->currentPathStack->expects($this->at(0))
			->method('getPath')
			->willReturn('/some/path');

		$this->request->expects($this->at(0))
			->method('getClientIp')
			->willReturn('::1');

		$this->requestStack->expects($this->at(0))
			->method('getCurrentRequest')
			->willReturn($this->request);
		
		$configFactory = $this->getConfigFactory([]);

		$restrictIpService = New RestrictIpService($this->currentUser, $this->currentPathStack, $configFactory, $this->requestStack);

		$this->assertSame('::1', $restrictIpService->getCurrentUserIp(), 'User IP address is properly reported');
	}

	/**
	 * @covers ::getCurrentPath
	 */
	public function testGetCurrentPath()
	{
		$this->currentPathStack->expects($this->at(0))
			->method('getPath')
			->willReturn('/some/path');

		$this->request->expects($this->at(0))
			->method('getClientIp')
			->willReturn('::1');

		$this->requestStack->expects($this->at(0))
			->method('getCurrentRequest')
			->willReturn($this->request);
		
		$configFactory = $this->getConfigFactory([]);

		$restrictIpService = New RestrictIpService($this->currentUser, $this->currentPathStack, $configFactory, $this->requestStack);

		$this->assertSame('/some/path', $restrictIpService->getCurrentPath(), 'Correct current path is properly reported');
	}

	private function getConfigFactory(array $settings)
	{
		return $this->configFactory = $this->getConfigFactoryStub([
			'restrict_ip.settings' => $settings,
		]);
	}
}
