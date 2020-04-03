from pbkdf2 import PBKDF2
import uuid
import re
from rijndael.cipher.crypt import new
from rijndael.cipher.blockcipher import MODE_CBC
from Crypto.Cipher import DES
import zlib
import argparse
import struct
import os
import pefile
import hashlib


parser = argparse.ArgumentParser(description='Parse nanocore samples')

parser.add_argument("--sample", help="raw nanocore sample to parse", required=False)
parser.add_argument("--dump_dir", help="directory to dump plugins parsed from nanocore", required=False)
parser.add_argument("--config_rsrc", help="raw resource file", required=False)
parser.add_argument("--guid", help="required if only using the config_rsrc", required=False)

args = parser.parse_args()

def ByteToHex(byteStr):     
    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def parse_config(decrypted_conf):
	i = 0
	is_key = True
	dict_key = ""
	dict_val = ""
	config_dict = {}

	plugins = decrypted_conf.split("\x00\x00\x4D\x5A")
	# remove first snippet as its junk code
	plugins = plugins[1:]
	
	# Add the MZ header back cuz python is hard
	# remove the config struct at the end of the file
	while i < len(plugins):
		plugins[i] = '\x4D\x5A' + plugins[i]
		if "\x07\x3E\x00\x00\x00" in plugins[i] and i == len(plugins)-1:
			plugins[i] = plugins[i].split("\x07\x3E\x00\x00\x00")[0]
		
		i += 1
	
	# 
	config_dict["NonStandard_PluginCount"] = len(plugins)
	
	# ensure that all the plugins parse properly
	path = os.getcwd()
	
	# write the plugins to disk
	if args.dump_dir is not "":
		fullpath = os.path.join(path, args.dump_dir)
		# TODO: how to make this not error out when a directory already exists?
		os.mkdir(fullpath)
		
		i = 0
		os.chdir(fullpath)
		while i < len(plugins):
			print("[+] extracting plugin {} from nanocore sample {}".format(i, args.sample))
			with open("plugin_"+ str(i), "w") as f:
				f.write(plugins[i])
			i += 1 
		
		os.chdir("..")

	logging_rule = re.search("\x0c.KeyboardLogging(?P<logging>.*?)\x0c", decrypted_conf)
	logging = logging_rule.group('logging')
	if ord(logging[1]):
		config_dict['KeyboardLogging'] = True
	else:
		config_dict['KeyboardLogging'] = False
	
	buildtime_rule = re.search("\x0c.BuildTime(?P<length>.)(?P<buildtime>.*?)\x0c", decrypted_conf)
	buildtime = buildtime_rule.group('buildtime')
	config_dict["BuildTime"] = buildtime

	version_rule = re.search("\x0c.Version.(?P<length>.)(?P<version>.*?)\x0c", decrypted_conf)
	version = version_rule.group('version')
	version_length = version_rule.group('length')
	if len(version) == ord(version_length):
		config_dict["Version"] = version

	mutex_rule = re.search("\x0c.Mutex.(?P<mutex>.*?)\x0c", decrypted_conf)
	mutex = mutex_rule.group('mutex')
	config_dict["Mutex"] = mutex
	
	default_group_rule = re.search("\x0c.DefaultGroup\x0c(?P<length>.)(?P<defaultgroup>.*?)\x0c", decrypted_conf)
	default_group = default_group_rule.group('defaultgroup')
	default_group_length = default_group_rule.group('length')
	if len(default_group) == ord(default_group_length):
		config_dict["DefaultGroup"] = default_group
	
	primary_connection_host_rule = re.search("\x0c.PrimaryConnectionHost\x0c(?P<length>.)(?P<primaryconnectionhost>.*?)\x0c", decrypted_conf)
	primary_connection_host = primary_connection_host_rule.group('primaryconnectionhost')
	primary_connection_host_length = primary_connection_host_rule.group('length')
	if len(primary_connection_host) == ord(primary_connection_host_length):
		config_dict["PrimaryConnection"] = primary_connection_host

	backup_connection_host_rule = re.search("\x0c.BackupConnectionHost\x0c(?P<length>.)(?P<backupconnectionhost>.*?)\x0c", decrypted_conf)
	backup_connection_host = backup_connection_host_rule.group('backupconnectionhost')
	backup_connection_host_length = backup_connection_host_rule.group('length')
	if len(backup_connection_host) == ord(backup_connection_host_length):
		config_dict["BackupConnection"] = backup_connection_host

	connection_port_rule = re.search("\x0c.ConnectionPort.(?P<connectionport>.*?)\x0c", decrypted_conf)
	connection_port = connection_port_rule.group("connectionport")
	connection_port = struct.unpack("<H", connection_port)[0]
	config_dict["ConnectionPort"] = connection_port

	run_on_startup_rule = re.search("\x0c.RunOnStartup(?P<runonstartup>.*?)\x0c", decrypted_conf)
	run_on_startup = run_on_startup_rule.group("runonstartup")
	if ord(run_on_startup[1]):
		config_dict["RunOnStartup"] = True
	else:
		config_dict["RunOnStartup"] = False
	
	request_elevation_rule = re.search("\x0c.RequestElevation(?P<requestelevation>.*?)\x0c", decrypted_conf)
	request_elevation = request_elevation_rule.group("requestelevation")
	if ord(request_elevation[1]):
		config_dict["RequestElevation"] = True
	else:
		config_dict["RequestElevation"] = False
	
	bypass_rule = re.search("\x0c.BypassUserAccountControl(?P<bypassuseraccountcontrol>.*?)\x0c", decrypted_conf)
	bypass = bypass_rule.group("bypassuseraccountcontrol")
	if ord(bypass[1]):
		config_dict["BypassUAC"] = True
	else:
		config_dict["BypassUAC"] = False

	clear_zone_identifier_rule = re.search("\x0c.ClearZoneIdentifier(?P<clearzoneidentifier>.*?)\x0c", decrypted_conf)
	clear_zone_identifier = clear_zone_identifier_rule.group("clearzoneidentifier")
	if ord(clear_zone_identifier[1]):
		config_dict["ClearZoneIdentifier"] = True
	else:
		config_dict["ClearZoneIdentifier"] = False
	
	clear_access_control_rule = re.search("\x0c.ClearAccessControl(?P<clearaccesscontrol>.*?)\x0c", decrypted_conf)
	clear_access_control = clear_access_control_rule.group("clearaccesscontrol")
	if ord(clear_access_control[1]):
		config_dict["ClearAccessControl"] = True
	else:
		config_dict["ClearAccessControl"] = False

	set_critical_process_rule = re.search("\x0c.SetCriticalProcess(?P<setcriticalprocess>.*?)\x0c", decrypted_conf)
	set_critical_process = set_critical_process_rule.group("setcriticalprocess")
	if ord(set_critical_process[1]):
		config_dict["SetCriticalProcess"] = True
	else:
		config_dict["SetCriticalProcess"] = False
	
	prevent_system_sleep_rule = re.search("\x0c.PreventSystemSleep(?P<preventsystemsleep>.*?)\x0c", decrypted_conf)
	prevent_system_sleep = prevent_system_sleep_rule.group("preventsystemsleep")
	if ord(prevent_system_sleep[1]):
		config_dict["PreventSystemSleep"] = True
	else:
		config_dict["PreventSystemSleep"] = False

	activate_away_mode_rule = re.search("\x0c.ActivateAwayMode(?P<activateawaymode>.*?)\x0c", decrypted_conf)
	activate_away_mode = activate_away_mode_rule.group("activateawaymode")
	if ord(activate_away_mode[1]):
		config_dict["ActivateAwayMode"] = True
	else:
		config_dict["ActivateAwayMode"] = False
	
	enable_debug_mode_rule = re.search("\x0c.EnableDebugMode(?P<enabledebugmode>.*?)\x0c", decrypted_conf)
	enable_debug_mode = enable_debug_mode_rule.group("enabledebugmode")
	if ord(enable_debug_mode[1]):
		config_dict["EnableDebugMode"] = True
	else:
		config_dict["EnableDebugMode"] = False
	
	run_delay_rule = re.search("\x0c.RunDelay(?P<rundelay>.*?)\x0c", decrypted_conf)
	run_delay = run_delay_rule.group("rundelay")
	config_dict["RunDelay"] = struct.unpack("<H", run_delay[0:2])[0]

	connect_delay_rule = re.search("\x0c.ConnectDelay(?P<connectdelay>.*?)\x0c", decrypted_conf)
	connect_delay = connect_delay_rule.group("connectdelay")
	config_dict["ConnectDelay"] =  connect_delay

	restart_delay_rule = re.search("\x0c.RestartDelay(?P<restartdelay>.*?)\x0c", decrypted_conf)
	restart_delay = restart_delay_rule.group("restartdelay")
	config_dict["RestartDelay"] =  restart_delay

	timeout_interval_rule = re.search("\x0c.TimeoutInterval(?P<timeoutinterval>.*?)\x0c", decrypted_conf)
	timeout_interval = timeout_interval_rule.group("timeoutinterval")
	config_dict["TimeoutInterval"] =  timeout_interval
	
	keep_alive_timeout_rule = re.search("\x0c.KeepAliveTimeout(?P<keepalivetimeout>.*?)\x0c", decrypted_conf)
	keep_alive_timeout = keep_alive_timeout_rule.group("keepalivetimeout")
	config_dict["KeepAliveTimeout"] =  keep_alive_timeout

	mutex_timeout_rule = re.search("\x0c.MutexTimeout(?P<mutextimeout>.*?)\x0c", decrypted_conf)
	mutex_timeout = mutex_timeout_rule.group("mutextimeout")
	config_dict["MutexTimeout"] =  mutex_timeout

	lan_timeout_rule = re.search("\x0c\x0aLanTimeout(?P<lantimeout>.*?)\x0c", decrypted_conf)
	lan_timeout = lan_timeout_rule.group("lantimeout")
	config_dict["LanTimeout"] =  lan_timeout

	wan_timeout_rule = re.search("\x0c\x0aWanTimeout(?P<wantimeout>.*?)\x0c", decrypted_conf)
	wan_timeout = wan_timeout_rule.group("wantimeout")
	config_dict["WanTimeout"] =  wan_timeout

	buffer_size_rule = re.search("\x0c\x0aBufferSize(?P<buffersize>.*?)\x0c", decrypted_conf)
	buffer_size = buffer_size_rule.group("buffersize")
	config_dict["BufferSize"] =  buffer_size

	max_packet_size_rule = re.search("\x0c.MaxPacketSize(?P<maxpacketsize>.*?)\x0c", decrypted_conf)
	max_packet_size = max_packet_size_rule.group("maxpacketsize")
	config_dict["MaxPacketSize"] =  max_packet_size
	
	threshold_rule = re.search("\x0c.GCThreshold(?P<threshold>.*?)\x0c", decrypted_conf)
	threshold = threshold_rule.group("threshold")
	config_dict["GCThreshold"] =  threshold

	custom_dns_rule = re.search("\x0c.UseCustomDnsServer(?P<customdns>.*?)\x0c", decrypted_conf)
	custom_dns = custom_dns_rule.group("customdns")
	if ord(custom_dns[1]):
		config_dict["UseCustomDnsServer"] = True
	else:
		config_dict["UseCustomDnsServer"] = False
	
	primary_dns_rule = re.search("\x0c.PrimaryDnsServer\x0c(?P<length>.)(?P<primarydns>.*?)\x0c", decrypted_conf)
	primary_dns = primary_dns_rule.group("primarydns")
	primary_dns_length = primary_dns_rule.group("length")
	if len(primary_dns) == ord(primary_dns_length):
		config_dict["PrimaryDnsServer"] = primary_dns

	secondary_dns_rule = re.search("\x0c.BackupDnsServer\x0c(?P<length>.)(?P<secondarydns>.*?)", decrypted_conf)
	secondary_dns = secondary_dns_rule.group("secondarydns")
	secondary_dns_length = secondary_dns_rule.group("length")
	if len(secondary_dns) == ord(secondary_dns_length):
		config_dict["BackupDnsServer"] = secondary_dns

	return config_dict


def decrypt_config(coded_config, key):
	data = coded_config[24:]
	decrypt_key = key[:8]
	cipher = DES.new(decrypt_key, DES.MODE_CBC, decrypt_key)
	raw_config = cipher.decrypt(data)
	new_data = raw_config[5:]
	decompressed_config =  zlib.decompress(new_data, -15)
	return decompressed_config
	

def derive_pbkdf2(key, salt, iv_length, key_length, iterations):
	generator = PBKDF2(key, salt, iterations)
	derived_iv = generator.read(iv_length)
	derived_key = generator.read(key_length)
	return derived_iv, derived_key


def main():
	if args.sample is not "":
		nanocore_sample = pefile.PE(args.sample)
		for rsrc in nanocore_sample.DIRECTORY_ENTRY_RESOURCE.entries:
			for entry in rsrc.directory.entries:
				if entry.id:
					offset = entry.directory.entries[0].data.struct.OffsetToData
					size = entry.directory.entries[0].data.struct.Size
					raw_config_data = nanocore_sample.get_memory_mapped_image()[offset:offset+size]
					print("[+] extracted encrypted config from PE resource")

	elif args.config_rsrc is not "":
		if parser.guid is "":
			print("[!] if a raw resource is being passed the PE guid must be passed as well")
		raw_config_data = open(args.config_rsrc, 'rb').read()
	
	
	if args.guid == "":
		print("[!] a GUID is required for the nanocore sample")
		os.Exit(1)
		
	guid = uuid.UUID(args.guid).bytes_le

	# AES encrypted key
	encrypted_key = raw_config_data[4:20]
	
	# rfc2898 derive IV and key
	div, dkey = derive_pbkdf2(guid, guid, 16, 16, 8)
	
	# init new rijndael cipher
	rjn = new(dkey, MODE_CBC, div, blocksize=len(encrypted_key))
	
	# decrypt the config encryption key
	final_key = rjn.decrypt(encrypted_key)

	# decrypt the config
	decrypted_conf = decrypt_config(raw_config_data, final_key)
	config_dict = parse_config(decrypted_conf)
	for v, k in config_dict.items():
		print("[+] Config param {}: {}".format(v, k))

	with open('config_out.bin', 'wb') as out:
		out.write(decrypted_conf) 

if __name__ == "__main__":
	main()