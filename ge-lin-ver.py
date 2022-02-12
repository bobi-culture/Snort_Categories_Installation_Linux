#----------------- import section -------------------

import subprocess, os, os.path
from os import path

import mysql.connector
from mysql.connector import (connection)


curr_dir = os.getcwd();

#------------------ Welcome Note -----------------

def welcome_func():

    os.system ("clear");

    f = open("welcome.txt", "r")
    print(f.read())

#------------------ Check SNORT & Apache & MySQL exist ------------------

welcome_func();

apache_dir_exist = (os.path.exists("/var/www/html"));
apache_service = subprocess.call(["systemctl", "is-active", "--quiet", "apache2"]);

mysql_dir_exist = (os.path.exists("/usr/bin/mysql"));
mysql_service = subprocess.call(["systemctl", "is-active", "--quiet", "mysql"]);

if (apache_dir_exist):

    print("Apache server directory seems exist ...");

else:

    print("Apache server directory does not exist !!!");

if (apache_service == 0):

    print("Apache Service is running.");

else:

    print("Apache Service is not running !!!");

if (mysql_dir_exist):

    print("It seems, Mysql is installed.");
    mysql_check_1 = True;

else:

    print("Mysql is not installed !!!");

if (mysql_service == 0):

    print("Mysql Service is running.");
    mysql_check_2 = True;

else:

    print("Mysql Service is not running !!!");


print ("\n Checking necessary and relative files ... \n\n");
print ("It's working ....   Please be patient !!! \n\n\n\n");

if (mysql_check_1 or mysql_check_2):

	print ("It seems needed packages is located in correct location and related service is running. Fine! \n");

else:

	os.system ("clear");
	print ("				--------------  !!!  WARNING  !!!  ------------- ");
	print ("\n\n The source package is NOT located in properly area! \n");
	print ("\n\n Related services is not running !!! Script will be terminated. \n");
	os.sys.exit();

#------------------ Creating Snort User, DB Tables and so on ------------------

mydb1 = mysql.connector.connect(
  host="localhost",
  user="root",
  password="");

mycursor = mydb1.cursor();
me1 = mycursor.execute;

me1("CREATE USER 'snort'@'localhost' IDENTIFIED BY '';")
me1("create database snort;");
me1("GRANT ALL ON snort.* TO 'snort'@'localhost';");
#me("update user set File_Priv = 'Y' where user = 'snort';");
me1("flush privileges;"); 


mydb2 = mysql.connector.connect(
  host="localhost",
  user="snort",
  password="",
  database="snort");

mycursor = mydb2.cursor();
me2 = mycursor.execute;

me2("use snort;"); 
me2("CREATE TABLE `schema` (vseq INT NOT NULL, ctime DATETIME NOT NULL, PRIMARY KEY (vseq))");
me2("CREATE TABLE `event` (sid INT UNSIGNED NOT NULL, cid INT UNSIGNED NOT NULL, signature INT UNSIGNED NOT NULL, timestamp DATETIME NOT NULL, PRIMARY KEY (sid,cid), INDEX sig (signature), INDEX time (timestamp))");
me2("CREATE TABLE `signature` (sig_id INT UNSIGNED NOT NULL AUTO_INCREMENT, sig_name VARCHAR(255) NOT NULL, sig_class_id INT UNSIGNED NOT NULL, sig_priority INT UNSIGNED, sig_rev INT UNSIGNED, sig_sid INT UNSIGNED, sig_gid INT UNSIGNED, PRIMARY KEY (sig_id), INDEX sign_idx (sig_name(20)), INDEX sig_class_id_idx (sig_class_id))");
me2("CREATE TABLE sig_reference (sig_id INT UNSIGNED NOT NULL, ref_seq INT UNSIGNED NOT NULL, ref_id INT UNSIGNED NOT NULL, PRIMARY KEY(sig_id, ref_seq))");
me2("CREATE TABLE reference (ref_id INT UNSIGNED NOT NULL AUTO_INCREMENT, ref_system_id INT UNSIGNED NOT NULL, ref_tag TEXT NOT NULL, PRIMARY KEY (ref_id))");
me2("CREATE TABLE reference_system (ref_system_id INT UNSIGNED NOT NULL AUTO_INCREMENT, ref_system_name VARCHAR(20), PRIMARY KEY (ref_system_id))");
me2("CREATE TABLE sig_class (sig_class_id INT UNSIGNED NOT NULL AUTO_INCREMENT, sig_class_name VARCHAR(60) NOT NULL, PRIMARY KEY (sig_class_id), INDEX (sig_class_id), INDEX (sig_class_name))");
me2("CREATE TABLE sensor (sid INT UNSIGNED NOT NULL AUTO_INCREMENT, hostname TEXT, interface TEXT, filter	TEXT, detail TINYINT, encoding TINYINT, last_cid INT UNSIGNED NOT NULL, PRIMARY KEY (sid))");
me2("CREATE TABLE iphdr (sid INT UNSIGNED NOT NULL, cid INT UNSIGNED NOT NULL, ip_src INT UNSIGNED NOT NULL, ip_dst INT UNSIGNED NOT NULL, ip_ver TINYINT UNSIGNED, ip_hlen TINYINT UNSIGNED, ip_tos TINYINT  UNSIGNED, ip_len SMALLINT UNSIGNED, ip_id SMALLINT UNSIGNED, ip_flags TINYINT UNSIGNED, ip_off SMALLINT UNSIGNED, ip_ttl TINYINT  UNSIGNED, ip_proto TINYINT UNSIGNED NOT NULL, ip_csum SMALLINT UNSIGNED, PRIMARY KEY (sid,cid), INDEX ip_src (ip_src), INDEX ip_dst (ip_dst))");
me2("CREATE TABLE tcphdr (sid INT UNSIGNED NOT NULL, cid INT UNSIGNED NOT NULL, tcp_sport SMALLINT UNSIGNED NOT NULL, tcp_dport SMALLINT UNSIGNED NOT NULL, tcp_seq INT UNSIGNED, tcp_ack INT UNSIGNED, tcp_off TINYINT UNSIGNED, tcp_res TINYINT UNSIGNED, tcp_flags TINYINT UNSIGNED NOT NULL, tcp_win SMALLINT UNSIGNED, tcp_csum SMALLINT UNSIGNED, tcp_urp SMALLINT UNSIGNED, PRIMARY KEY (sid,cid), INDEX tcp_sport (tcp_sport), INDEX tcp_dport (tcp_dport), INDEX tcp_flags (tcp_flags))");
me2("CREATE TABLE udphdr (sid INT UNSIGNED NOT NULL, cid INT UNSIGNED NOT NULL, udp_sport SMALLINT UNSIGNED NOT NULL, udp_dport SMALLINT UNSIGNED NOT NULL, udp_len SMALLINT UNSIGNED, udp_csum SMALLINT UNSIGNED, PRIMARY KEY (sid,cid), INDEX udp_sport (udp_sport), INDEX udp_dport (udp_dport))");
me2("CREATE TABLE icmphdr (sid INT UNSIGNED NOT NULL, cid INT UNSIGNED NOT NULL, icmp_type TINYINT UNSIGNED NOT NULL, icmp_code TINYINT UNSIGNED NOT NULL, icmp_csum SMALLINT UNSIGNED, icmp_id SMALLINT UNSIGNED, icmp_seq SMALLINT UNSIGNED, PRIMARY KEY (sid,cid), INDEX icmp_type (icmp_type))");
me2("CREATE TABLE opt (sid INT UNSIGNED NOT NULL, cid INT UNSIGNED NOT NULL, optid INT UNSIGNED NOT NULL, opt_proto   TINYINT  UNSIGNED NOT NULL, opt_code TINYINT UNSIGNED NOT NULL, opt_len SMALLINT, opt_data TEXT, PRIMARY KEY (sid,cid,optid))");
me2("CREATE TABLE simovits_critic (port_no varchar(15), port_name varchar(7), description varchar(150))");
me2("CREATE TABLE sans_org_critic (port_no varchar(15), description varchar(150), port_name varchar(7))");
me2("CREATE TABLE wikipedia_info (port_no varchar(15), protocol varchar(10), status varchar(20), description varchar(150))");
me2("CREATE TABLE iana_info (port_no varchar(15), protocol varchar(10), status varchar(20), description varchar(150))");
me2("CREATE TABLE security_space_info (port_no varchar(15), protocol varchar(10), status varchar(20), description varchar(150))");
me2("CREATE TABLE data (sid INT UNSIGNED NOT NULL, cid INT UNSIGNED NOT NULL, data_payload TEXT, PRIMARY KEY (sid,cid))");
me2("CREATE TABLE encoding (encoding_type TINYINT UNSIGNED NOT NULL, encoding_text TEXT NOT NULL, PRIMARY KEY (encoding_type))");
me2("CREATE TABLE detail  (detail_type TINYINT UNSIGNED NOT NULL, detail_text TEXT NOT NULL, PRIMARY KEY (detail_type))");

me2("INSERT INTO `schema` (vseq, ctime) VALUES ('107', now())");
me2("INSERT INTO detail (detail_type, detail_text) VALUES (0, 'fast')");
me2("INSERT INTO detail (detail_type, detail_text) VALUES (1, 'full')");
me2("INSERT INTO encoding (encoding_type, encoding_text) VALUES (0, 'hex')");
me2("INSERT INTO encoding (encoding_type, encoding_text) VALUES (1, 'base64')");
me2("INSERT INTO encoding (encoding_type, encoding_text) VALUES (2, 'ascii')");

me2("LOAD DATA LOCAL INFILE '" + os.path.join(curr_dir, "simovits_Critic_0.csv") + "' INTO TABLE simovits_critic FIELDS TERMINATED BY ',' ");
me2("LOAD DATA LOCAL INFILE '" + os.path.join(curr_dir, "ORIG_Sign_Final_1.csv") + "' INTO TABLE signature FIELDS TERMINATED BY ',' ");
me2("LOAD DATA LOCAL INFILE '" + os.path.join(curr_dir, "SANS_Critic_0.csv") + "' INTO TABLE sans_org_critic FIELDS TERMINATED BY ','  ");
me2("LOAD DATA LOCAL INFILE '" + os.path.join(curr_dir, "Wikipedia_info_0.csv") + "' INTO TABLE wikipedia_info FIELDS TERMINATED BY ','  ");
me2("LOAD DATA LOCAL INFILE '" + os.path.join(curr_dir, "IANA_info_0.csv") + "' INTO TABLE iana_info FIELDS TERMINATED BY ','  ");
me2("LOAD DATA LOCAL INFILE '" + os.path.join(curr_dir, "Security_Space_0.csv") + "' INTO TABLE security_space_info FIELDS TERMINATED BY ','  ");

me2("CREATE INDEX iphdr_idx ON iphdr (cid)");
me2("CREATE INDEX tcphdr_idx ON tcphdr (cid)");
me2("CREATE INDEX udphdr_idx ON udphdr (cid)");
me2("CREATE INDEX icmphdr_idx ON icmphdr (cid)");
me2("CREATE INDEX event_idx ON icmphdr (cid)");

#------------------ Program Body (Functions call) ------------------

print("\n\n The installation is completed properly ...");
print("\n\n Now, you can use Snort DB for IDS purposes.");
print("\n\n Congrats !!!");

#--------------------------------------------------------------------