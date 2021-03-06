OpenVPN Secure Deployment Tool
=======
OpenVPN Secure Deployment Tool installs and configures OpenVPN 2.3 with strong security settings without sacrificing performance or speed. Compatible with RHEL/CentOS 6, Debian 7 wheezy, and Ubuntu 12+. Thoroughly tested on Amazon Web Service. Perfect for deploying on a new Virtual Private Server. Pre-made configuration files included for Windows, Linux, and mobile clients. 

####Features
* User friendly interface
* Completely configurable
* Red Hat 6, CentOS 6, Debian wheezy, and Ubuntu 12+ compatibility
* Strong TLS cipher suites, forward secrecy
* Various settings to guard against MITM attacks
* Strict iptables firewall
* Easily generate and revoke client certificates

#####Files
`setup.py` is the installation script.<br>
`settings.ini` contains various configurable options used by `setup.py`.<br>
`firewall.sh` is a strict, iptables firewall script.<br> 
`openssl.cnf` contains the OpenSSL settings used by the script.<br>

`conf` contains the following configuration files:<br>
&nbsp;&nbsp;|--`conf/server.conf` holds the OpenVPN server settings.<br>
&nbsp;&nbsp;|--`conf/client.conf` contains suitable settings for Linux clients.<br>
&nbsp;&nbsp;|--`conf/client.ovpn` contains suitable settings for Windows clients.<br>
&nbsp;&nbsp;|--`conf/mobile.ovpn` contains suitable settings for Android and iOS clients.

**Note:** This tool does not do general system hardening. Ensure you have Python 2.6+ and the latest release of OpenSSL prior to running it. This tool requires superuser privileges. If SELinux is in enforcing mode, you will not be able to change the port OpenVPN can bind to (ie. you must use port 1194 or disable SELinux).

####Usage
1. Clone this repo: `git clone https://github.com/aeibrahim/osdt`
2. Edit `settings.ini` with your preferred options.
3. Run the installation script: `python setup.py --install`. If you enabled a passphrase for the CA certificate, you will be prompted multiple times for a passphrase, otherwise everything will be automated.
4. Keys and certificates will be placed in `/etc/openvpn/pki`.
5. A tarball containing files required by the client will be created. Securely transfer it to your client. 
6. To generate additional client certificates, edit the client section of `settings.ini` and then run `python setup.py --client-gen`.
7. To revoke certificates, set revoke_cert in `settings.ini` to the name of the client certificate you wish to revoke, then run `python setup.py --revoke`.
8. To uninstall and remove all associated files, run `python setup.py --remove`.

Logging is disabled by default. To enable it, edit `/etc/openvpn/server.conf` then restart the OpenVPN daemon.

If connecting with Android or iOS clients, OpenVPN Connect app does not support fragment options, so make sure you disable it on the server.

#####Configuring Clients

For Windows clients, you will need to download and install OpenVPN 2.3.X Windows Installer from <a href="http://openvpn.net/index.php/download/community-downloads.html" target="_blank">here</a>. Move your client private key, client certificate, CA certificate, TLS auth key, and client.ovpn file to `C:\Program Files\OpenVPN\config` folder. and run the openvpn-gui program in the bin folder with administrator privileges.

For Linux clients, the simplest method of connecting to an OpenVPN server is with Network Manager. First, you will need to download the OpenVPN plugin for Network Manager and then import your client configuration file.

On RHEL/CentOS/Fedora, do the following:<br>
`yum -y install NetworkManager-openvpn NetworkManager-openvpn-gnome`<br>
`service NetworkManager restart`<br>

On Debian/Ubuntu, do the following:<br>
`apt-get update && apt-get -y install network-manager-openvpn network-manager-openvpn-gnome`<br>
`/etc/init.d/network-manager restart`<br>

Then, use Network Manager to add a new VPN connection and import your client config file. It should automatically reflect your settings in the GUI window. After that, simply connect to the VPN server and everything should be operational.

For Android or iOS clients, download the OpenVPN Connect app and import your .ovpn configuration profile.

#####Known Issues
Logs may display *Deprecated TLS cipher name* error. Since there is a 256 character limit on line lengths in configuration files, using the IANA naming results in having to drop a few cipher suites. Therefore, you can safely ignore this error message.

OpenVPN Connect mobile app returns an error when using ECDSA certificates. Use RSA certificates instead.

#####Future
OpenVPN does not support ECDHE+ECDSA cipher suites at the moment. When support is added, this tool will be updated to generate ECDSA client certificates and cipher suites will be changed to ones that include ECDHE.

License
=======
"OpenVPN" is a trademark of OpenVPN Technologies, Inc. OpenVPN is distributed under the GNU General Public License version 2. By using OpenVPN or any of its bundled components, you agree to be bound by the conditions of the license for each respective component.

OpenVPN Secure Deployment Tool is a standalone project without any ties to OpenVPN Technologies, Inc. This is free software; you are encouraged to use it, modify it, improve it, and/or redistribute it under the terms of the GNU General Public License version 3 as published by the Free Software Foundation.

This tool is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License version 3 along with this tool; if not, visit
https://www.gnu.org/licenses/gpl.html.
