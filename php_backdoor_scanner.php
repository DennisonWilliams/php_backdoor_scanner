<?php

// configuration
$config['target_dir'] = "/home";
$config['output_file'] = "output/results_".date("Y-m-d").".txt";
$config['false_positives_file'] = "false_positives.txt";
$config['email'] = "sysop@radicaldesigns.org";
$config['sha1sums_db'] = 'sha1sums.db';
$config['verbose'] = 0;
$config['excludes'] = array( '.', '..', '.git', '.gitignore', '.svn');

// files are suspicious if they contain any of these strings
$suspicious_strings = array(
    'c99shell', 'phpspypass', 'Owned',
    'hacker', 'h4x0r', '/etc/passwd',
    'uname -a', 'eval(base64_decode(',
    '(0xf7001E)?0x8b:(0xaE17A)',
    'd06f46103183ce08bbef999d3dcc426a',
    'rss_f541b3abd05e7962fcab37737f40fad8');
$suspicious_files = array();

// false positives
if(file_exists($config['false_positives_file'])) {
    $contents = file_get_contents($config['false_positives_file']);
    $false_positives = explode("\n", $contents);
} else {
    $false_positives = false;
}

// sha1sums
$sha1sums = false;
if (file_exists($config['sha1sums_db'])) {
	try {
		$query = 'SELECT count(*) AS count FROM sha1sums where sha1sum=?';
		$dbhandle = new PDO('sqlite:'. $config['sha1sums_db']);
		$dbhandle->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$stmt = $dbhandle->prepare($query);
		$config['sha1_select_stmt'] = $stmt;
		$sha1sums = true;
	}
	catch (PDOException $e) {
		print 'Unable to select the sha1sum count from the database('. $config['sha1sums_db'] .'): '. 
			$e->getMessage();
		exit(1);
	}
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
		global $sha1sums;
    
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

						// Is there a sha1sum of the file?
            $false = false;
						if($sha1sums && is_file_sha1_whitelisted($full_filename)) {
							$false= true;
						}	
            // is it a false positive?
            else if($false_positives) {
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

function is_file_sha1_whitelisted($file) {
	global $config;

	// Get file sha1sum
	$sha1 = sha1_file($file);

	// See if it exists in the DB
	/*
	$query = 'SELECT a.name AS application, v.name AS version, s.name AS file FROM sha1sums AS s '.
		'LEFT JOIN applications AS a ON a.anid = s.anid '.
		'LEFT JOIN versions AS v ON v.avid = s.avid '.
		'WHERE s.sha1sum=?';
	*/

	try {
		$config['sha1_select_stmt']->execute(array($sha1));
		$row = $config['sha1_select_stmt']->fetch(PDO::FETCH_ASSOC);
		return $row['count'];
	}
	catch (PDOException $e) {
		print 'Unable to select the sha1sum count from the database('. $config['sha1sums_db'] .'): '. 
			$e->getMessage();
		exit(1);
	}
}

function add_sha1sums($source_directory) {
	global $config;

	if (!file_exists($config['sha1sums_db'])) {
		print "argument add-sha1sums expects there to be an existing sha1sum database (".
			$config['sha1sums_db'] .") but it could not be found.  Maybe you meant to ".
			"use the rebuild-sha1sums argument?\n";
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

	try {
		$dbhandle = new PDO('sqlite:'. $config['sha1sums_db']);
		$dbhandle->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		// AVD = Application Version Directory
		while(false !== ($AVD = $ANDH->read())) {
			if(array_search($AVD, $config['excludes']) === false) {

				if (is_dir($source_directory.'/'.$AVD)) {
					_add_sha1sums($dbhandle, $AND, $AVD, $source_directory.'/'.$AVD);
				}
			}
		}
		unset($dbhandle);
	}
	catch (PDOException $e) {
		print 'Unable to add sha1sumes to the database('. $config['sha1sums_db'] .'): '. 
			$e->getMessage();
		exit(1);
	}

	print "[] Added sha1sums.\n";

}

function _get_application_name_id($dbhandle, $AND) {
	// Check if it is in the DB, otherise add it
	$query = 'SELECT anid FROM applications WHERE name=?';
	$stmt = $dbhandle->prepare($query);
	$stmt->execute(array($AND));
	$row = $stmt->fetch(PDO::FETCH_ASSOC);

	if ($row === false || !array_key_exists('anid', $row)) {
		$query = 'INSERT INTO applications(name) VALUES(?)';
		$stmt = $dbhandle->prepare($query);
		$stmt->execute(array($AND));
		return $dbhandle->lastInsertid();
	}

	return $row['anid'];
}

function _get_application_version_id($dbhandle, $AVD, $ANID) {
	// Check if it is in the DB, otherise add it
	$query = 'SELECT avid FROM versions WHERE name=? AND anid=?';
	$stmt = $dbhandle->prepare($query);
	$stmt->execute(array($AVD, $ANID));
	$row = $stmt->fetch(PDO::FETCH_ASSOC);

	if ($row === false || !array_key_exists('avid', $row)) {
		$query = 'INSERT INTO versions(name, anid) VALUES(?,?)';
		$stmt = $dbhandle->prepare($query);
		$stmt->execute(array($AVD, $ANID));
		return $dbhandle->lastInsertid();
	}

	return $row['avid'];
}

function _add_sha1sums($dbhandle, $AND, $AVD, $path) {
	global $config;

	// open directory
	$d = @dir($path);
	if($d == false) {
		echo "\n[] Failed to open directory ".$path.", skipping";
		return;
	}

	while(false !== ($filename = $d->read())) {
		if ($config['verbose']) {
			print "[verbose] Examining $filename.\n";
		}
		// skip . and ..
		if(array_search($filename, $config['excludes']) === false) {
			$full_filename = $d->path."/".$filename;

			// is it another directory?
			if(is_dir($full_filename)) {
				// scan it
				_add_sha1sums($dbhandle, $AND, $AVD, $full_filename);
			} else if (is_file($full_filename)) {
				if (!preg_match(":$AND/$AVD/(.*):", $full_filename, $matches)) {
					//print "preg_match(\":$AND/$AVD/\(.*\):\", \$full_filename, \$matches)\n";
					print "There was a problem getting the application file name from $full_filename\n";
					exit(1);
				}

				$ANID =	_get_application_name_id($dbhandle, $AND);
				$query = 'INSERT INTO sha1sums(sha1sum, name, anid, avid) VALUES(?,?,?,?)';
				$stmt = $dbhandle->prepare($query);
				$stmt->execute(array(sha1_file($full_filename), $matches[1],
					$ANID, _get_application_version_id($dbhandle, $AVD, $ANID)));
			}
			// If its not a file and its not a directory to we really care?
		}
	}
}

function dump_sha1sums() {
	global $config;

	if (!file_exists($config['sha1sums_db'])) {
		print "The database file (". $config['sha1sums_db'] .") does not exist.\n";
		exit(1);
	}

	$sha1sums = 'SELECT a.name AS application, v.name AS version, s.name AS file, s.sha1sum AS sha1 FROM sha1sums AS s '.
		'LEFT JOIN applications AS a ON a.anid = s.anid '.
		'LEFT JOIN versions AS v ON v.avid = s.avid';

	try {
		$dbhandle = new PDO('sqlite:'. $config['sha1sums_db']);
		$dbhandle->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$stmt = $dbhandle->query($sha1sums);
		foreach ($stmt as $row) {
			//print $row['a.name'] .'('. $row['v.name'] .') '. $row['s.name'] .' => '. $row['s.sha1sum'] ."\n";
			print $row['application'] .'('. $row['version'] .') '. $row['file'] .' => '. $row['sha1'] ."\n";
		}
		unset($dbhandle);
	} 
	catch (PDOException $e) {
		print 'Unable to select the sha1sums from the database('. $config['sha1sums_db'] .'): '. 
			$e->getMessage();
		exit(1);
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
	// DB Schema
	$applications = 'CREATE TABLE applications( '.
		'anid integer PRIMARY KEY, '. // anid is an alias for ROWID
		'name text UNIQUE NOT NULL)';

	$versions = 'CREATE TABLE versions( '.
		'avid integer PRIMARY KEY, '. // avid is an alias for ROWID
		'name text NOT NULL, '.
		'anid integer, '.
		'FOREIGN KEY(anid) REFERENCES applications(anid))';

	$sha1sums = 'CREATE TABLE sha1sums( '.
		'sha1sum text NOT NULL, '. // This is actually not unique because the same
															 // file can exist in multiple versions of a 
															 // application.
		'name text NOT NULL, '.
		'anid integer, '.
		'avid integer, '.
		'FOREIGN KEY(anid) REFERENCES applications(anid), '.
		'FOREIGN KEY(avid) REFERENCES versions(avid))';

	try {
		$dbhandle = new PDO('sqlite:'. $config['sha1sums_db']);
		$dbhandle->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$dbhandle->exec($applications);
		$dbhandle->exec($versions);
		$dbhandle->exec($sha1sums);
		unset($dbhandle);
	} 
	catch (PDOException $e) {
		print 'Unable to initialize the database('. $config['sha1sums_db'] .'): '. 
			$e->getMessage();
		exit(1);
	}

	print "[] Sha1sums Database created.\n";
	add_sha1sums($source_directory);
}

// TODO: process command line arguments (rebuild database, etc)
$options = getopt('', array(
	'add-sha1sums:', 
	'rebuild-sha1sums:', 
	'dump-sha1sums',
	'target-dir:', 
	'verbose')
);

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

if (array_key_exists('dump-sha1sums', $options)) {
	dump_sha1sums();
	exit(0);
} 

if (array_key_exists('target-dir', $options) && !is_dir($options['target-dir'])) {
	print 'target-dir exppects a diirectory path to look for suspicious files and '.
		"none was specified.\n";
	exit(1);
} else if (array_key_exists('target-dir', $options) && is_dir($options['target-dir'])) {
	$config['target_dir'] = $options['target-dir'];
}

if (array_key_exists('verbose', $options)) {
	$config['verbose'] = true;
}

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
