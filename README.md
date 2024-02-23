# vsAIPDB
A AbuseIPDB PHP Class

Setup Script
```
require('vsAIPDB.php');
```

Check IP Address
```
$client = new vsAIPDB(API_KEY);
$client->checkIP($ipAddr);
```

Report IP Address
```
$ipAddr = 'IP you want to report';
$cats = 'Array of categories, can get from $client->getCats()';
$comment = 'Why do you want to report this IP';
$timestamp = 'Date/Time in ISO 8601 format';

$client = new vsAIPDB(API_KEY);
$client->reportIP($ipAddr, $cats, $comment, $timestamp);
```
