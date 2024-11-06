


















void compat_banner(struct ssh *ssh, const char *version)
{
	int i;
	static struct {
		char	*pat;
		int	bugs;
	} check[] = {
		{ "OpenSSH_2.*," "OpenSSH_3.0*," "OpenSSH_3.1*",	SSH_BUG_EXTEOF|SSH_OLD_FORWARD_ADDR| SSH_BUG_SIGTYPE}, { "OpenSSH_3.*",	SSH_OLD_FORWARD_ADDR|SSH_BUG_SIGTYPE }, { "Sun_SSH_1.0*",	SSH_BUG_NOREKEY|SSH_BUG_EXTEOF| SSH_BUG_SIGTYPE}, { "OpenSSH_2*," "OpenSSH_3*," "OpenSSH_4*",		SSH_BUG_SIGTYPE }, { "OpenSSH_5*",		SSH_NEW_OPENSSH|SSH_BUG_DYNAMIC_RPORT| SSH_BUG_SIGTYPE}, { "OpenSSH_6.6.1*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE}, { "OpenSSH_6.5*," "OpenSSH_6.6*",	SSH_NEW_OPENSSH|SSH_BUG_CURVE25519PAD| SSH_BUG_SIGTYPE}, { "OpenSSH_7.4*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE| SSH_BUG_SIGTYPE74}, { "OpenSSH_7.0*," "OpenSSH_7.1*," "OpenSSH_7.2*," "OpenSSH_7.3*," "OpenSSH_7.5*," "OpenSSH_7.6*," "OpenSSH_7.7*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE}, { "OpenSSH*",		SSH_NEW_OPENSSH }, { "*MindTerm*",		0 }, { "3.0.*",		SSH_BUG_DEBUG }, { "3.0 SecureCRT*",	SSH_OLD_SESSIONID }, { "1.7 SecureFX*",	SSH_OLD_SESSIONID }, { "1.2.18*," "1.2.19*," "1.2.20*," "1.2.21*," "1.2.22*",		SSH_BUG_IGNOREMSG }, { "1.3.2*", SSH_BUG_IGNOREMSG }, { "Cisco-1.*",		SSH_BUG_DHGEX_LARGE| SSH_BUG_HOSTKEYS }, { "*SSH Compatible Server*", SSH_BUG_PASSWORDPAD }, { "*OSU_0*," "OSU_1.0*," "OSU_1.1*," "OSU_1.2*," "OSU_1.3*," "OSU_1.4*," "OSU_1.5alpha1*," "OSU_1.5alpha2*," "OSU_1.5alpha3*",	SSH_BUG_PASSWORDPAD }, { "*SSH_Version_Mapper*", SSH_BUG_SCANNER }, { "PuTTY_Local:*," "PuTTY-Release-0.5*," "PuTTY_Release_0.5*," "PuTTY_Release_0.60*," "PuTTY_Release_0.61*," "PuTTY_Release_0.62*," "PuTTY_Release_0.63*," "PuTTY_Release_0.64*", SSH_OLD_DHGEX }, { "FuTTY*",		SSH_OLD_DHGEX }, { "Probe-*", SSH_BUG_PROBE }, { "TeraTerm SSH*," "TTSSH/1.5.*," "TTSSH/2.1*," "TTSSH/2.2*," "TTSSH/2.3*," "TTSSH/2.4*," "TTSSH/2.5*," "TTSSH/2.6*," "TTSSH/2.70*," "TTSSH/2.71*," "TTSSH/2.72*",	SSH_BUG_HOSTKEYS }, { "WinSCP_release_4*," "WinSCP_release_5.0*," "WinSCP_release_5.1," "WinSCP_release_5.1.*," "WinSCP_release_5.5," "WinSCP_release_5.5.*," "WinSCP_release_5.6," "WinSCP_release_5.6.*," "WinSCP_release_5.7," "WinSCP_release_5.7.1," "WinSCP_release_5.7.2," "WinSCP_release_5.7.3," "WinSCP_release_5.7.4", SSH_OLD_DHGEX }, { "ConfD-*", SSH_BUG_UTF8TTYMODE }, { "Twisted_*",		0 }, { "Twisted*",		SSH_BUG_DEBUG }, { NULL,			0 }




























































































	};

	
	ssh->compat = 0;
	for (i = 0; check[i].pat; i++) {
		if (match_pattern_list(version, check[i].pat, 0) == 1) {
			debug_f("match: %s pat %s compat 0x%08x", version, check[i].pat, check[i].bugs);
			ssh->compat = check[i].bugs;
			return;
		}
	}
	debug_f("no match: %s", version);
}

char * compat_cipher_proposal(struct ssh *ssh, char *cipher_prop)
{
	if (!(ssh->compat & SSH_BUG_BIGENDIANAES))
		return cipher_prop;
	debug2_f("original cipher proposal: %s", cipher_prop);
	if ((cipher_prop = match_filter_denylist(cipher_prop, "aes*")) == NULL)
		fatal("match_filter_denylist failed");
	debug2_f("compat cipher proposal: %s", cipher_prop);
	if (*cipher_prop == '\0')
		fatal("No supported ciphers found");
	return cipher_prop;
}

char * compat_pkalg_proposal(struct ssh *ssh, char *pkalg_prop)
{
	if (!(ssh->compat & SSH_BUG_RSASIGMD5))
		return pkalg_prop;
	debug2_f("original public key proposal: %s", pkalg_prop);
	if ((pkalg_prop = match_filter_denylist(pkalg_prop, "ssh-rsa")) == NULL)
		fatal("match_filter_denylist failed");
	debug2_f("compat public key proposal: %s", pkalg_prop);
	if (*pkalg_prop == '\0')
		fatal("No supported PK algorithms found");
	return pkalg_prop;
}

char * compat_kex_proposal(struct ssh *ssh, char *p)
{
	if ((ssh->compat & (SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX)) == 0)
		return p;
	debug2_f("original KEX proposal: %s", p);
	if ((ssh->compat & SSH_BUG_CURVE25519PAD) != 0)
		if ((p = match_filter_denylist(p, "curve25519-sha256@libssh.org")) == NULL)
			fatal("match_filter_denylist failed");
	if ((ssh->compat & SSH_OLD_DHGEX) != 0) {
		if ((p = match_filter_denylist(p, "diffie-hellman-group-exchange-sha256," "diffie-hellman-group-exchange-sha1")) == NULL)

			fatal("match_filter_denylist failed");
	}
	debug2_f("compat KEX proposal: %s", p);
	if (*p == '\0')
		fatal("No supported key exchange algorithms found");
	return p;
}

