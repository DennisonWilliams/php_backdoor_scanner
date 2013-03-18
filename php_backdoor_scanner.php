<?php

// configuration
$config['target_dir'] = "/home";
$config['output_file'] = "/home/wordpress-base/scripts/php_backdoor_scanner/output/results_".date("Y-m-d").".txt";
$config['false_positives_file'] = "/home/wordpress-base/scripts/php_backdoor_scanner/false_positives.txt";
$config['email'] = "sysop@radicaldesigns.org";
$config['sha1sums_db'] = 'sha1sums.db';

// files are suspicious if they contain any of these strings
$suspicious_strings = array(
    'c99shell', 'phpspypass', 'Owned',
    'hacker', 'h4x0r', '/etc/passwd',
    'uname -a', 'eval(base64_decode(',
    '(0xf7001E)?0x8b:(0xaE17A)',
    'd06f46103183ce08bbef999d3dcc426a',
    'rss_f541b3abd05e7962fcab37737f40fad8',
    '(0x4eF1)?0xBf9C0');
$suspicious_files = array();

// false positives
if(file_exists($config['false_positives_file'])) {
    $contents = file_get_contents($config['false_positives_file']);
    $false_positives = explode("\n", $contents);
} else {
    $false_positives = false;
}

// returns whether or not it's a php file
function is_php_file($filename) {
    return substr($filename, -4) == ".php" || 
        substr($filename, -5) == ".php4" || 
        substr($filename, -5) == ".php5";
}

// recursively scan a directory for malware
$dir_count = 0;
function backdoor_scan($path) {
    global $suspicious_strings;
    global $suspicious_files;
    global $config;
    global $false_positives;
    global $dir_count;
    
    echo ".";
    $dir_count++;
    
    // open directory
    $d = @dir($path);
    if($d == false) {
        echo "\n[] Failed to open directory ".$path.", skipping";
        return;
    }
    while(false !== ($filename = $d->read())) {
        // skip . and ..
        if($filename != "." && $filename != "..") {
            $full_filename = $d->path."/".$filename;
            
            // is it a false positive?
            $false = false;
            if($false_positives) {
                if(in_array($full_filename, $false_positives))
                    $false = true;
            }
            if(!$false) {
                // is it another directory?
                if(is_dir($full_filename)) {
                    // scan it
                    backdoor_scan($full_filename);
                } else {        
                    // is it a php file?
                    if(is_php_file($filename)) {
                        // scan this file
                        $contents = file_get_contents($full_filename);
                        $suspicious = false;
                        foreach($suspicious_strings as $string) {
                            if(strpos($contents, $string) != false)
                                $suspicious = true;
                        }
                        if($suspicious) {
                            // found a suspicious file!
                            echo "\n[] *** Suspicious file found: ".$full_filename;
                            
                            // record this in the output file
                            // note: i'm opening and closing this file each time so you can view the file before the entire scan is done
                            $of = fopen($config['output_file'], "a");
                            fwrite($of, $full_filename."\n");
                            fclose($of);

                            // save it the array
                            $suspicious_files[] = $full_filename;
                        }
                    }
                }
            }
        }
    }
}

/**
 *  Sha1sums can be used to keep known good hashes of known good code.  We 
 *  maintain a databases of these hashes and expect the source from which
 *  the hashes are derived to be in the format <application_name>/<version>/
 */

function add_sha1sums($source_directory) {
	global $config;

	if (!file_exists($config['sha1sums_sb'])) {
		print "argument add-sha1sums expects there to be an existing sha1sum database (".
			$config['sha1sums_db'] .") but it could not be found.  Maybe you meant to ".
			"use the rebuild-sha1sums argument?\n";
		exit(1);
	}

	$dbhandle = sqlite_open($config['sha1sums_sb'], 0666, $error);
	//$dbhandle = sqlite3::open($config['sha1sums_sb'], 0666, $error);
	if (!$dbhandle) {
		print "There was an issue accessing the sha1sum database: $error\n";
		exit(1);
	}
	
	// AND = Application Name Directory
	$AND = basename($source_directory);

	// ANDH = Application Name Directory Handle
	$ANDH = @dir($source_directory);
	if($ANDH == false) {
		print "Unable to add sha1sums because the source directory passed in could ".
			"not be opened\n";
		exit(1);
	}

	// Get the Application Name ID
	$ANID = _get_application_name_id($dbhandle, $AND);

	// Get the Application Version ID
	$AVID = _get_application_name_id($dbhandle, $AVD, $ANID);

	// AVD = Application Version Directory
	while(false !== ($AVD = $ANDH->read())) {
		if (is_dir($source_directory.'/'.$AVD)) {
			_add_sha1sums($dbhandle, $ANID, $AVID, $source_directory.'/'.$AVD);
		}
	}

	sqlite_close($dbhandle);
}

function _get_application_name_id($dbhandle, $AND) {
	// Check if it is in the DB, otherise add it
	$query = 'SELECT anid FROM applications WHERE name="'. $AND .'"';
	$result = sqlite_query($dbhandle, $query);
	if (!$result) {
		print "Could not find the applications name $AND in the database\n";
		exit(1);
	}

	$row = sqlite_fetch_array($result, SQLITE_ASSOC);
	if (!array_key_exists('anid', $row)) {
		$query = 'INSERT INTO applications(name) VALUES("'. $AND .'")';
		$ok = sqlite_exec($dbhandle, $query, $error);
		if (!$ok) {
			print "Unable to add application name($AND) to the database\n";
			exit(1);
		}

		// There unfortunately does not seem to be a way to get the recently
		// inserted primary key from the result of an insert statement
		$query = 'SELECT anid FROM applications WHERE name="'. $AND .'"';
		$result = sqlite_query($dbhandle, $query);
		if (!$result) {
			print "Could not find the application name $AND in the database\n";
			exit(1);
		}
		$row = sqlite_fetch_array($result, SQLITE_ASSOC);
	}

	return $row['anid'];
}

function _get_application_version_id($dbhandle, $AVD, $ANID) {
	// Check if it is in the DB, otherise add it
	$query = 'SELECT avid FROM versions WHERE name="'. $AVD .'" AND anid='. $ANID;
	$result = sqlite_query($dbhandle, $query);
	if (!$result) {
		print "Could not find the application version for $AVD in the database\n";
		exit(1);
	}

	$row = sqlite_fetch_array($result, SQLITE_ASSOC);
	if (!array_key_exists('avid', $row)) {
		$query = 'INSERT INTO versions(name, anid) VALUES("'. $AVD .'",'. $ANID .')';
		$ok = sqlite_exec($dbhandle, $query, $error);
		if (!$ok) {
			print "Unable to add application version($AVD) to the database\n";
			exit(1);
		}

		// There unfortunately does not seem to be a way to get the recently
		// inserted primary key from the result of an insert statement
		$query = 'SELECT avid FROM versions WHERE name="'. $AVD .'" AND anid='. $ANID;
		$result = sqlite_query($dbhandle, $query);
		if (!$result) {
			print "Could not find the application version $AVD in the database\n";
			exit(1);
		}
		$row = sqlite_fetch_array($result, SQLITE_ASSOC);
	}

	return $row['avid'];
}

function _add_sha1sums($dbhandle, $ANID, $AVID, $path) {
	$excludes = array( '.', '..', '.git', '.gitignore', '.svn');

	// open directory
	$d = @dir($path);
	if($d == false) {
		echo "\n[] Failed to open directory ".$path.", skipping";
		return;
	}

	while(false !== ($filename = $d->read())) {
		// skip . and ..
		if(array_search($filename, $excludes) === false) {
			$full_filename = $d->path."/".$filename;

			// is it another directory?
			if(is_dir($full_filename)) {
				// scan it
				_add_sha1sums($dbhandle, $AND, $AVD, $full_filename);
			} else if (is_file($full_filename)) {
				if (!preg_match(":$AND/$AVD/\(.*\):", $full_filename, $matches)) {
					print "There was a problem getting the application file name from $full_filename\n";
					exit(1);
				}

				$query = 'INSERT INTO sha1sum(sha1sum, afn, aid, avid) VALUES("'.
					sha1_file($full_filename) .'","'. $full_filename .'","'. $ANID .','. $AVID .')';
				$ok = sqlite_exec($dbhandle, $query, $error);
				if (!$ok) {
					print "Unable to add the sha1sum for the application file($full_filename) to the ".
						"database.\n";
					exit(1);
				}
			}
			// If its not a file and its not a directory to we really care?
		}
	}
}

function rebuild_sha1sums($source_directory) {
	global $config;

	if (file_exists($config['sha1sums_db'])) {
		print "The database file (". $config['sha1sums_db'] .") exists already.  ".
			"Please backup or remove it first.\n";
		exit(1);
	}

	$error = '';
	$dbhandle = sqlite_open($config['sha1sums_db'], 0666, $error);
	//$dbhandle = sqlite3::open($config['sha1sums_db'], 0666, $error);
	if (!$dbhandle) {
		print "There was an issue accessing the sha1sum database: $error\n";
		exit(1);
	}

	// DB Schema
	$applications = 'CREATE TABLE applications( '.
		'anid integer PRIMARY KEY, '. // anid is an alias for ROWID
		'name text UNIQUE NOT NULL)';

	$ok = sqlite_exec($dbhandle, $applications, $error);
	if (!$ok) {
		print "Unable to add applications table($applications): $error.\n";
		exit(1);
	}

	$versions = 'CREATE TABLE versions( '.
		'avid integer PRIMARY KEY, '. // avid is an alias for ROWID
		'name text NOT NULL, '.
		'anid integer, '.
		'FOREIGN KEY(anid) REFERENCES applications(anid))';

	$ok = sqlite_exec($dbhandle, $versions, $error);
	if (!$ok) {
		print "Unable to add versions table($versions): $error.\n";
		exit(1);
	}

	$sha1sums = 'CREATE TABLE sha1sums( '.
		'sha1sum text UNIQUE NOT NULL, '.
		'name text NOT NULL, '.
		'anid integer, '.
		'avid integer, '.
		'FOREIGN KEY(anid) REFERENCES applications(anid), '.
		'FOREIGN KEY(avid) REFERENCES versions(avid))';

	$ok = sqlite_exec($dbhandle, $sha1sums, $error);
	if (!$ok) {
		print "Unable to add versions table($sha1sums): $error.\n";
		exit(1);
	}
	
	sqlite_close($dbhandle);

	print "[] Sha1sums Database created.\n";

	add_sha1sums($source_directory);
}

// TODO: process command line arguments (rebuild database, etc)
$options = getopt('', array('add-sha1sums:', 'rebuild-sha1sums:', 'dump-sha1sums'));

/*
class Sha1SumsDB extends SQLite3 {
	function __construct() {
		global $config;
		$this->open($config['sha1sums_db']);
	}
}
$db = new Sha1SumsDB();
*/

if (array_key_exists('add-sha1sums', $options) && !is_dir($options['add-sha1sums'])) {
	print "add-sha1sums expects a directory path argument containing known good ".
		"application source code and this was not found\n";
	exit(1);
} else if (array_key_exists('add-sha1sums', $options) && is_dir($options['add-sha1sums'])) {
	add_sha1sums($options['add-sha1sums']);
}

if (array_key_exists('rebuild-sha1sums', $options) && !is_dir($options['rebuild-sha1sums'])) {
	print "rebuild-sha1sums expects a directory path argument containing known good ".
		"application source code and this was not found\n";
	exit(1);
} else if (array_key_exists('rebuild-sha1sums', $options) && is_dir($options['rebuild-sha1sums'])) {
	rebuild_sha1sums($options['rebuild-sha1sums']);
}
die("DEBUG: not running checks.\n". print_r($options, 1)."\n");


// start with an empty output file
$of = fopen($config['output_file'], "w");
fclose($of);

// if the target_dir has a trailing /, remove it
if(substr($config['target_dir'], -1) == "/")
    $config['target_dir'] = substr($config['target_dir'], 0, strlen($config['target_dir'])-1);

// scan it all
backdoor_scan($config['target_dir']);

// if we found any, email it to sysop
if(sizeof($suspicious_files) > 0) {
    if(!empty($config['email'])) {
        $body = '';
        foreach($suspicious_files as $filename) {
            $body .= $filename."\r\n";
        }
        mail($config['email'], "Found ".sizeof($suspicious_files)." suspicious files on ".date("Y-m-d"),
            $body, "From: ".$config['email']."\r\nReply-To: ".$config['email']."\r\n");
    }
}

// finished 
echo "\n\n";
if(sizeof($suspicious_files > 0)) {
    echo "[] Scan complete. A list of suspicious files is stored in: ".$config['output_file']."\n";
} else {
    echo "[] Scan complete. No suspicious files were found.";
}
echo "\n";

?>
