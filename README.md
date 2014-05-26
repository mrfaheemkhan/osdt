OpenVPN Secure Deployment Tool
=======
OpenVPN Secure Deployment Tool installs and configures OpenVPN 2.3 with strong security settings without sacrificing performance or speed. Compatible with RHEL/CentOS 6, Debian 7 wheezy, and Ubuntu 12+. Thoroughly tested on Amazon Web Service. Perfect for deploying on a new Virtual Private Server. Pre-made configuration files included for Windows, Linux, and mobile clients. 

####Features
* User friendly interface
* Completely configurable
* Red Hat 6, CentOS 6, Debian wheezy, and Ubuntu 12+ compatibility
* Strong TLS cipher suites, forward secrecy
* 256-bit AES encryption, SHA384 message authentication
* CA certificate with choice between 4096-bit RSA or ECDSA with any elliptic curve supported by OpenSSL
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
7. If connecting with Android clients, OpenVPN Android app does not support fragment options, so make sure you disable it on both the server and client.
8. To revoke certificates, set revoke_cert in `settings.ini` to the name of the client certificate you wish to revoke, then run `python setup.py --revoke`.
9. To uninstall and remove all associated files, run `python setup.py --remove`.

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
