<?php
	class vsAIPDB {
		private $apiKey; // Your AbuseIPDB API Key
		private $baseURL = 'https://api.abuseipdb.com/api/v2/';

		public function __construct($apiKey) {
			$this->apiKey = $apiKey;
		}

		public function getCats(){
			$cats = [
				1	=> ['t'=>'DNS Compromise', 'd'=>'Altering DNS records resulting in improper redirection'],
				2	=> ['t'=>'DNS Poisoning', 'd'=>'Falsifying domain server cache (cache poisoning)'],
				3	=> ['t'=>'Fraud Orders', 'd'=>'Fraudulent orders'],
				4	=> ['t'=>'DDoS Attack', 'd'=>'Participating in distributed denial-of-service (usually part of botnet)'],
				5	=> ['t'=>'FTP Brute-Force'],
				6	=> ['t'=>'Ping of Death', 'd'=>'Oversized IP packet'],
				7	=> ['t'=>'Phishing', 'd'=>'Phishing websites and/or email'],
				8	=> ['t'=>'Fraud VoIP'],
				9	=> ['t'=>'Open Proxy', 'd'=>' Open proxy, open relay, or Tor exit node'],
				10	=> ['t'=>'Web Spam', 'd'=>' Comment/forum spam, HTTP referer spam, or other CMS spam'],
				11	=> ['t'=>'Email spam', 'd'=>' Spam email content, infected attachments, and phishing emails. Note: Limit comments to only relevent information (instead of log dumps) and be sure to remove PII if you want to remain anonymous'],
				12	=> ['t'=>'Blog Spam', 'd'=>'CMS blog comment spam'],
				13	=> ['t'=>'VPN IP', 'd'=>'Conjunctive category'],
				14	=> ['t'=>'Port scan', 'd'=>'Scanning for open ports and vulnerable services'],
				15	=> ['t'=>'Hacking'],
				16	=> ['t'=>'SQL Injection', 'd'=>'Attemps at SQL injection'],
				17	=> ['t'=>'Spoofing', 'd'=>'Email sender spoofing'],
				18	=> ['t'=>'Brute-Force', 'd'=>'Credential brute-force attacks on webpage logins and services like SSH, FTP, SIP, SMTP, RDP, etc. This category is seperate from DDoS attacks'],
				19	=> ['t'=>'Bad Web Bot', 'd'=>'Webpage scraping (for email addresses, content, etc) and crawlers that do not honor robots.txt. Excessive requests and user agent spoofing can also be reported here'],
				20	=> ['t'=>'Exploited Host', 'd'=>'Host is likely infected with malware and being used for other attacks or to host malicious content. The host owner may not be aware of the compromise. This category is often used in combination with other attack categories'],
				21	=> ['t'=>'Web App Attack', 'd'=>'Attempts to probe for or exploit installed web applications such as a CMS like WordPress/Drupal, e-commerce solutions, forum software, phpMyAdmin and various other software plugins/solutions'],
				22	=> ['t'=>'SSH', 'd'=>'Secure Shell (SSH) abuse. Use this category in combination with more specific categories'],
				23	=> ['t'=>'IoT Targeted', 'd'=>'Abuse was targeted at an "Internet of Things" type device. Include information about what type of device was targeted in the comments']
			];

			return $cats;
		}

		// Function to handle cURL requests
		private function curlRequest($endpoint, $para = [], $method='GET') {
			$url = ($this->baseURL . $endpoint);
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_HTTPHEADER, [
				'Accept: application/json',
				'Key: ' . $this->apiKey,
			]);

			if ($method == 'POST') {
				curl_setopt($ch, CURLOPT_POST, true);
				curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($para));
			}
			// Default to GET
			else {
				$url .= '?' . http_build_query($para);
			}
			curl_setopt($ch, CURLOPT_URL, $url);

			$response = curl_exec($ch);
			curl_close($ch);

			return json_decode($response, true); // Decode response into an associative array
		}

		/**
      Function to check an IP address
		 *
		 * @param string $ip The IP address to report.
     */
		public function checkIP($ip, $maxAges=90, $verbose=false) {
			$para = [
				'ipAddress'		=> $ip,
				'maxAgeInDays'	=> $maxAges
			];
			if($verbose) $para['verbose'] = '';

			$response = $this->curlRequest('check', $para);
			
			return $response['data'] ?? false;
		}

		/**
		 * Function to report an IP address.
		 *
		 * @param string $ip The IP address to report.
		 * @param array $categories The categories of abuse.
		 * @param string $comment The comment describing the abuse.
		 * @param string|null $timestamp The timestamp of the abuse event.
		 * @return array|bool The response data, or false on failure.
		 */
		public function reportIP($ip, $categories, $comment, $timestamp = null) {
			// Use the current date/time if $timestamp is null
			if ($timestamp === null) {
				$timestamp = (new DateTime('now', new DateTimeZone('UTC')))->format('c');
			}

			$para = [
				'ip'			=> $ip,
				'categories'	=> implode(',', (array)$categories),
				'comment'		=> $comment,
				'timestamp'		=> $timestamp
			];

			return $this->curlRequest('report', $para, 'POST');
		}
	}
?>
