#!/usr/bin/env python
# This script is offered without warranty of any kind. Execute at your own peril.
# Version 1.0

__author__ = "Ali Ibrahim"
__email__ = "ali@infosecsociety.com"

import subprocess
from optparse import OptionParser
from platform import linux_distribution as linux_distro
from ConfigParser import SafeConfigParser
from time import sleep
from os import devnull, chdir

# function to handle message status coloring
def message(msg, status_code):
	if status_code == 0:
		print "\033[92m[+]\033[0m " + msg # green
	elif status_code == 1:
		print "\033[91m[-]\033[0m " + msg # red
	elif status_code == 5:
		print "\033[93m[-]\033[0m " + msg # yellow

# function to read settings from settings.ini into a dictionary
def get_settings(filename):
	parser = SafeConfigParser()
	parser.read(filename)
	options = {}
	for section_name in parser.sections():
		for key,value in parser.items(section_name):
			options[key] = value
	return options

# function to setup firewall
def firewall_setup(settings):
	message("Configuring Firewall...", 0)
	sleep(1.5)
	subprocess.call(['sed', '-i', '-e', 's/VPNPORT/{0}/'.format(settings['port']), '-e', 's/X.X.X.X/{0}/'.format(settings['private_subnet']), '-e', 's/DISTRO/{0}/'.format(settings['distro']), '-e', 's/PROTO/{0}/g'.format(settings['mode']), 'firewall.sh'])
	subprocess.call(['bash', 'firewall.sh']) # applies firewall rules from firewall script
	sleep(1.5)
	message("Enabling IP Forwarding...", 0)
	if settings['distro'] in ['Debian', 'Ubuntu']:
		subprocess.call(['sed', '-i', "s/#net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/", '/etc/sysctl.conf'])
	else:
		subprocess.call(['sed', '-i', "s/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/", '/etc/sysctl.conf'])
	sleep(1.5)
	if settings['disable_ipv6'] == 'True':
		message("Disabling IPv6...", 0)
		subprocess.call('echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf', shell=True)
		sleep(1.5)
	subprocess.call(['sysctl', '-p'], stderr=open(devnull), stdout=open(devnull))
	message("Firewall configuration complete.", 0)

# function to install openvpn and dependencies
def packages(settings):
	if settings['distro'] in ['CentOS', 'Red Hat', 'RHEL']:
		sleep(1.5)
		message("Adding EPEL repo...", 0)
		if settings['arch'] == 'x64':
			subprocess.call(['rpm', '-U', 'https://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm'], stderr=open(devnull), stdout=open(devnull))
		else:
			subprocess.call(['rpm', '-U', 'https://dl.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm'], stderr=open(devnull), stdout=open(devnull))
		message("Downloading required packages...", 0)
		sleep(1.5)
		try:
			subprocess.check_call(['yum', 'install', '-y', 'openvpn'])
		except:
			raise SystemExit(message("Failed to install required packages. Exiting...", 1))
		else:
			message("Packages successfully downloaded and installed.", 0)
	elif settings['distro'] in ['Debian', 'debian', 'Ubuntu', 'ubuntu']:
		message("Downloading required packages...", 0)
		sleep(1.5)
		try:
			subprocess.check_call(['apt-get', 'update'])
			subprocess.check_call(['apt-get', 'install', '-y', 'openvpn'])
		except:
			raise SystemExit(message("Failed to install required packages. Exiting...", 1))
		else:
			message("Packages successfully downloaded and installed.", 0)
			sleep(1.5)

# function to generate CA/server keys and certs
def pki_setup(settings):
	message("Configuring PKI...", 0)
	sleep(1.5)
	base_dir = '/etc/openvpn/pki/'
	subprocess.call(['mkdir', '-p', base_dir])
	openssl_file = 'openssl.cnf'
	subprocess.call(['openssl', 'dhparam', '-out', base_dir + 'dh.pem', '2048'])
	subprocess.call('touch {0}index.txt; echo 01 > {0}serial'.format(base_dir), shell=True)
	# CA
	message("Generating CA certificate and key...", 0)
	sleep(1.5)
	try:
		if settings['pk_alg'] in ['ecdsa', 'ECDSA']:
			subprocess.call(['openssl', 'ecparam', '-out', base_dir + 'ecc.param', '-name', settings['ec_curve']])
			if settings['ca_passphrase'] == 'True':
				subprocess.call(['openssl', 'req', '-new', '-x509', '-newkey', 'ec:{0}ecc.param'.format(base_dir), '-keyout', base_dir + 'ca.key', '-out', base_dir + 'ca.crt', '-days', settings['ca_expiry'], '-subj', '/CN={0}/name={1}'.format(settings['ca_common_name'],settings['ca_subject']), '-config', openssl_file])
			else:
				subprocess.call(['openssl', 'req', '-new', '-x509', '-nodes', '-newkey', 'ec:{0}ecc.param'.format(base_dir), '-keyout', base_dir + 'ca.key', '-out', base_dir + 'ca.crt', '-days', settings['ca_expiry'], '-subj', '/CN={0}/name={1}'.format(settings['ca_common_name'],settings['ca_subject']), '-config', openssl_file])
		elif settings['pk_alg'] in ['rsa', 'RSA']:
			if settings['ca_passphrase'] == 'True':
				subprocess.call(['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:4096', '-keyout', base_dir + 'ca.key', '-out', base_dir + 'ca.crt', '-days', settings['ca_expiry'], '-subj', '/CN={0}/name={1}'.format(settings['ca_common_name'],settings['ca_subject']), '-config', openssl_file])
			else:
				subprocess.call(['openssl', 'req', '-new', '-x509', '-nodes', '-newkey', 'rsa:4096', '-keyout', base_dir + 'ca.key', '-out', base_dir + 'ca.crt', '-days', settings['ca_expiry'], '-subj', '/CN={0}/name={1}'.format(settings['ca_common_name'],settings['ca_subject']), '-config', openssl_file])
	except:
		raise SystemExit(message("Failed to generate CA certificate. Exiting...", 1))
	else:
		subprocess.call(['openssl', 'ca', '-gencrl', '-out', base_dir + 'ca.crl', '-config', openssl_file])
		subprocess.call('cat {0}ca.crt {0}ca.crl > {0}crl.pem'.format(base_dir), shell=True)
		message("CA certificate and key successfully created.", 0)
		sleep(1.5)
	# Server
	message("Generating OpenVPN server certificate and key...", 0)
	sleep(1.5)
	try:
		subprocess.call(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', base_dir + 'server.key', '-out', base_dir + 'server.csr', '-subj', '/CN={0}/name={1}'.format(settings['server_common_name'],settings['server_subject']), '-config', openssl_file])
	except:
		raise SystemExit(message("Failed to generate server certificate. Exiting...", 1))
	else:
		subprocess.call(['openssl', 'ca', '-batch', '-in', base_dir + 'server.csr', '-out', base_dir + 'server.crt', '-days', settings['cert_expiry'], '-extensions', 'server', '-config', openssl_file])
		message("Server certificate and key successfully created and signed.", 0)
		sleep(1.5)
	# generate TLS auth key
	subprocess.call(['openvpn', '--genkey', '--secret', base_dir + 'tls-auth.key'])
	message("TLS authentication key successfully created.", 0)
	sleep(1.5)
	subprocess.call('chmod 400 /etc/openvpn/pki/*.key', shell=True)
	subprocess.call(['bash', '-c', 'chmod 444 /etc/openvpn/pki/*.{pem,crt}'])
	message("PKI setup complete.", 0)
	sleep(1.5)

# function to generate client certificates
def create_client_cert(settings):
	message("Generating client certificate and key...", 0)
	sleep(1.5)
	openssl_file = 'openssl.cnf'
	base_dir = '/etc/openvpn/pki/'
	try:
		subprocess.call(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', base_dir + settings['client_name'] + '.key', '-out', base_dir + settings['client_name'] + '.csr', '-subj', '/CN={0}/name={1}'.format(settings['client_common_name'],settings['client_subject']), '-config', openssl_file])
	except:
		raise SystemExit(message("Client certificate and key generation failed. Exiting...", 1))
	else:
		subprocess.call(['openssl', 'ca', '-batch', '-in', base_dir + settings['client_name'] + '.csr', '-out', base_dir + settings['client_name'] + '.crt', '-days', settings['cert_expiry'], '-config', openssl_file])
		message("Client certificate and key successfully created and signed.", 0)
		sleep(1.5)
	subprocess.call(['chmod', '400', base_dir + settings['client_name'] + '.key'])
	client_tar_file = '{0}.tar.gz'.format(settings['client_name'])
	# use different config files depending on OS of client
	if settings['client_os'] in ['Windows', 'windows']:
		subprocess.call(['sed', '-i', '-e', 's/SERVER/{0}/'.format(settings['remote_server']), '-e', 's/PORT/{0}/'.format(settings['port']), '-e', 's/MODE/{0}/'.format(settings['mode']), '-e', 's/ABC/{0}/'.format(settings['server_common_name']), '-e', 's/DEF/{0}/'.format(settings['server_subject']), 'conf/client.ovpn'])
		subprocess.call(['tar', '-czf', client_tar_file, '-C', 'conf', 'client.ovpn', '-C', base_dir, 'ca.crt', 'tls-auth.key', settings['client_name'] + '.crt', settings['client_name'] + '.key'])
	elif settings['client_os'] in ['Linux', 'linux']:
		subprocess.call(['sed', '-i', '-e', 's/SERVER/{0}/'.format(settings['remote_server']), '-e', 's/PORT/{0}/'.format(settings['port']), '-e', 's/MODE/{0}/'.format(settings['mode']), '-e', 's/ABC/{0}/'.format(settings['server_common_name']), '-e', 's/DEF/{0}/'.format(settings['server_subject']), 'conf/client.conf'])
		subprocess.call(['tar', '-czf', client_tar_file, '-C', 'conf', 'client.conf', '-C', base_dir, 'ca.crt', 'tls-auth.key', settings['client_name'] + '.crt', settings['client_name'] + '.key'])
	elif settings['client_os'] in ['Mobile', 'mobile']:
		subprocess.call(['sed', '-i', '-e', 's/SERVER/{0}/'.format(settings['remote_server']), '-e', 's/PORT/{0}/'.format(settings['port']), '-e', 's/MODE/{0}/'.format(settings['mode']), '-e', 's/ABC/{0}/'.format(settings['server_common_name']), '-e', 's/DEF/{0}/'.format(settings['server_subject']), 'conf/mobile.ovpn'])
		subprocess.call(['tar', '-czf', client_tar_file, '-C', 'conf', 'mobile.ovpn', '-C', base_dir, 'ca.crt', 'tls-auth.key',settings['client_name'] + '.crt', settings['client_name'] + '.key'])
	message("\033[91m{0}\033[0m packaged and ready for transfer.".format(client_tar_file), 0)

# function to configure OpenVPN server settings
def vpn_server_config(settings):
	message("Configuring OpenVPN...", 0)
	sleep(1.5)
	config_file = 'conf/server.conf'
	subprocess.call(['sed', '-i', '-e', 's/PORT/{0}/'.format(settings['port']), '-e', 's/MODE/{0}/'.format(settings['mode']), config_file])
	subprocess.call(['sed', '-i', '-e', 's/PRIVATE_SUBNET/{0}/'.format(settings['private_subnet']), '-e', 's/MAX/{0}/'.format(settings['max_clients']), config_file])
	subprocess.call(['sed', '-i', '-e', 's/SERVER1/{0}/'.format(settings['dns_1']), '-e', 's/SERVER2/{0}/'.format(settings['dns_2']), config_file])
	if settings['logging'] == 'True':
		subprocess.call(['sed', '-i', '-e', 's/\/dev\/null/\/var\/log\/openvpn.log/', config_file])
	subprocess.call(['cp', 'conf/server.conf', '/etc/openvpn/'])
	if settings['distro'] in ['CentOS', 'Red Hat', 'RHEL']:
		subprocess.call(['service', 'openvpn', 'start'])
		subprocess.call(['chkconfig', 'openvpn', 'on'])
	elif settings['distro'] in ['Debian', 'Ubuntu']:
		# add openvpn user and group w/ no shell
		subprocess.call(['useradd', '-r', 'openvpn', '-d', '/etc/openvpn/', '-M', '-U', '-s', '/usr/sbin/nologin', '-c', 'OpenVPN Server'])
		subprocess.call(['/etc/init.d/openvpn', 'start'])
	message("OpenVPN configuration complete.", 0)

# function to uninstall OpenVPN
def remove_all(settings):
	confirm = raw_input("Are you sure you wish to uninstall OpenVPN? [y/N] ")
	if confirm in ['Y', 'y']:
		message("Removing OpenVPN and associated files.", 5)
		sleep(1.5)
		# remove packages
		if settings['distro'] in ['CentOS', 'Red Hat', 'RHEL']:
			subprocess.call(['yum', '-y', 'erase', 'openvpn'])
		elif settings['distro'] in ['Debian', 'Ubuntu']:
			subprocess.call(['apt-get', 'purge', '-y', 'openvpn'])
			subprocess.call(['userdel', 'openvpn'])
		# delete associated files
		subprocess.call(['rm', '-rf', '/etc/openvpn/'])
		message("Uninstall complete!", 0)

# function to revoke client certificates
def revoke_cert(settings):
	base_dir = '/etc/openvpn/pki/'
	openssl_file = 'openssl.cnf'
	confirm = raw_input("Are you sure you wish to revoke {0}? [y/N] ".format(settings['revoke_cert']))
	if confirm in ['Y', 'y']:
		try:
			subprocess.call(['openssl', 'ca', '-revoke', base_dir + settings['revoke_cert'], '-keyfile', base_dir + 'ca.key', '-cert', base_dir + 'ca.crt', '-config', openssl_file])
		except:
			raise SystemExit(message("Failed to revoke specified certificate. Exiting...", 1))
		else:
			subprocess.call(['openssl', 'ca', '-gencrl', '-out', base_dir + 'ca.crl', '-config', openssl_file])
			subprocess.call('cat {0}ca.crt {0}ca.crl > {0}crl.pem'.format(base_dir), shell=True)	
			message("Certificate revocation successful.", 0)

def main():
	desc='''This tool securely deploys OpenVPN on RHEL 6, CentOS 6, Debian wheezy or Ubuntu 12+.'''
	parser = OptionParser(description=desc)
	parser.add_option('--install', help='installs OpenVPN', action='store_true', dest='install', default=False)
	parser.add_option('--remove', help='removes OpenVPN and associated files', action='store_true', dest='remove', default=False)
	parser.add_option('--client-gen',  help='generates a client certificate', action='store_true', dest='client_gen', default=False)
	parser.add_option('--revoke',  help='revokes a certificate', action='store_true', dest='revoke', default=False)
	parser.add_option('--version', help='show program version and exit', action='store_true', dest='version', default=False)
	(options, arguments) = parser.parse_args()

	if linux_distro()[0] not in ['CentOS', 'Red Hat Enterprise Linux Server', 'debian', 'Ubuntu']:
			raise SystemExit(message("Unsupported distribution. Exiting...", 1))
	else:
		settings = get_settings('settings.ini')
		if options.version is True:
			print 'OpenVPN Secure Deployment Tool version 1.0'
		elif options.install is True:
			subprocess.call(['clear'])
			print (' ' + 76 * '=')
			print '|{0:^75} |\n|{1:^75} |'.format('OpenVPN Secure Deployment Tool', 'by Ali Ibrahim')
			print (' ' + 76 * '=')
			sleep(1.25)
			message("Beginning Deployment...", 0)
			sleep(1.25)
			firewall_setup(settings)
			packages(settings)
			pki_setup(settings)
			create_client_cert(settings)
			vpn_server_config(settings)
			message("OpenVPN deployment complete. Enjoy!", 0)
		elif options.remove is True:
			remove_all(settings)
		elif options.client_gen is True:
			create_client_cert(settings)
		elif options.revoke is True:
			revoke_cert(settings)
		else:
			parser.print_help()
		
if __name__ == '__main__':
	main()
